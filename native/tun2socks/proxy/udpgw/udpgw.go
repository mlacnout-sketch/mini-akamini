package udpgw

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/url"
	"sync"
	"time"

	"github.com/xjasonlyu/tun2socks/v2/dialer"
	M "github.com/xjasonlyu/tun2socks/v2/metadata"
	"github.com/xjasonlyu/tun2socks/v2/proxy"
)

// BadVPN UDPGW Protocol Constants
const (
	flagKeepAlive = 0x01
	flagRebind    = 0x02
	flagDNS       = 0x04
	flagIPv6      = 0x08
)

func init() {
	proxy.RegisterProtocol("udpgw", Parse)
}

type Udpgw struct {
	addr    string
	manager *connManager
	mu      sync.Mutex
}

func New(addr string) *Udpgw {
	return &Udpgw{addr: addr}
}

func (u *Udpgw) DialContext(ctx context.Context, metadata *M.Metadata) (net.Conn, error) {
	return nil, fmt.Errorf("udpgw does not support TCP")
}

func (u *Udpgw) DialUDP(metadata *M.Metadata) (net.PacketConn, error) {
	u.mu.Lock()
	if u.manager == nil {
		u.manager = newConnManager(u.addr)
	}
	u.mu.Unlock()

	return u.manager.NewVirtualConn(metadata), nil
}

type connManager struct {
	addr     string
	tcpConn  net.Conn
	mu       sync.Mutex
	vConns   map[uint16]*virtualPacketConn
	vConnsMu sync.RWMutex
}

func newConnManager(addr string) *connManager {
	m := &connManager{
		addr:   addr,
		vConns: make(map[uint16]*virtualPacketConn),
	}
	go m.keepAliveLoop()
	return m
}

func (m *connManager) connect() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.tcpConn != nil {
		return nil
	}

	// Use a longer timeout for the shared TCP connection
	conn, err := dialer.DialContext(context.Background(), "tcp", m.addr)
	if err != nil {
		return err
	}
	m.tcpConn = conn
	go m.readLoop(conn)
	return nil
}

func (m *connManager) keepAliveLoop() {
	for {
		time.Sleep(20 * time.Second)
		m.mu.Lock()
		if m.tcpConn != nil {
			// BadVPN KeepAlive: [Len=1 (2b)] [Flags=KeepAlive (1b)]
			// Note: KeepAlive packet doesn't send ConID in original C implementation if length is 1
			buf := make([]byte, 3)
			binary.BigEndian.PutUint16(buf[0:2], 1)
			buf[2] = flagKeepAlive
			m.tcpConn.Write(buf)
		}
		m.mu.Unlock()
	}
}

func (m *connManager) readLoop(conn net.Conn) {
	defer func() {
		m.mu.Lock()
		if m.tcpConn == conn { m.tcpConn = nil }
		conn.Close()
		m.mu.Unlock()
	}()

	for {
		var lb [2]byte
		if _, err := io.ReadFull(conn, lb[:]); err != nil { return }
		
		packetLen := binary.BigEndian.Uint16(lb[:])
		if packetLen == 0 { continue }

		buf := make([]byte, packetLen)
		if _, err := io.ReadFull(conn, buf); err != nil { return }

		flags := buf[0]
		if (flags & flagKeepAlive) != 0 { continue }

		if len(buf) < 3 { continue }
		conID := binary.LittleEndian.Uint16(buf[1:3])

		// Logic from udpgw.c: connection_send_to_client (server -> client)
		// Header(3) + Address(4/16 + 2) + Payload
		pos := 3
		isIPv6 := (flags & flagIPv6) != 0
		ipLen := 4
		if isIPv6 { ipLen = 16 }
		
		if len(buf) < pos+ipLen+2 { continue }
		// We skip reading the address because we route by ConID
		pos += ipLen + 2
		
		payload := buf[pos:]

		m.vConnsMu.RLock()
		vConn, ok := m.vConns[conID]
		m.vConnsMu.RUnlock()

		if ok {
			vConn.putPacket(payload)
		}
	}
}

func (m *connManager) NewVirtualConn(metadata *M.Metadata) *virtualPacketConn {
	// Generate a unique ConID (using timestamp bits like badvpn-tun2socks)
	id := uint16(time.Now().UnixNano() & 0xFFFF)
	vc := &virtualPacketConn{
		manager:  m,
		metadata: metadata,
		conID:    id,
		ch:       make(chan []byte, 200),
	}
	m.vConnsMu.Lock()
	m.vConns[id] = vc
	m.vConnsMu.Unlock()
	return vc
}

type virtualPacketConn struct {
	manager  *connManager
	metadata *M.Metadata
	conID    uint16
	ch       chan []byte
}

func (v *virtualPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	ip := v.metadata.DstIP.AsSlice()
	var flags uint8
	ipLen := 4
	if len(ip) == 16 { 
		flags |= flagIPv6
		ipLen = 16
	}

	// BadVPN Client Header Structure:
	// [Flags 1b] [ConID 2b (LittleEndian)] [IP 4/16b] [Port 2b (BigEndian)]
	headerLen := 1 + 2 + ipLen + 2
	totalLen := headerLen + len(b)
	
	buf := make([]byte, 2 + totalLen)
	binary.BigEndian.PutUint16(buf[0:2], uint16(totalLen)) // Framing length
	buf[2] = flags
	binary.LittleEndian.PutUint16(buf[3:5], v.conID)
	copy(buf[5:5+ipLen], ip)
	binary.BigEndian.PutUint16(buf[5+ipLen:2+headerLen], uint16(v.metadata.DstPort))
	copy(buf[2+headerLen:], b)

	if err := v.manager.send(buf); err != nil { return 0, err }
	return len(b), nil
}

func (m *connManager) send(b []byte) error {
	if err := m.connect(); err != nil { return err }
	m.mu.Lock()
	defer m.mu.Unlock()
	_, err := m.tcpConn.Write(b)
	return err
}

func (v *virtualPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	select {
	case p := <-v.ch:
		return copy(b, p), v.metadata.UDPAddr(), nil
	case <-time.After(60 * time.Second):
		return 0, nil, fmt.Errorf("timeout")
	}
}

func (v *virtualPacketConn) putPacket(data []byte) {
	select {
	case v.ch <- data:
	default:
	}
}

func (v *virtualPacketConn) Close() error {
	v.manager.vConnsMu.Lock()
	delete(v.manager.vConns, v.conID)
	v.manager.vConnsMu.Unlock()
	return nil
}

func (v *virtualPacketConn) LocalAddr() net.Addr { return &net.UDPAddr{} }
func (v *virtualPacketConn) SetDeadline(t time.Time) error { return nil }
func (v *virtualPacketConn) SetReadDeadline(t time.Time) error { return nil }
func (v *virtualPacketConn) SetWriteDeadline(t time.Time) error { return nil }

func Parse(u *url.URL) (proxy.Proxy, error) {
	return New(u.Host), nil
}