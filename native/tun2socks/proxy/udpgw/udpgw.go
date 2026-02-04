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
	"github.com/xjasonlyu/tun2socks/v2/log"
	M "github.com/xjasonlyu/tun2socks/v2/metadata"
	"github.com/xjasonlyu/tun2socks/v2/proxy"
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
	return &Udpgw{
		addr: addr,
	}
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

// connManager handles the single shared TCP connection to the udpgw server
type connManager struct {
	addr       string
	tcpConn    net.Conn
	mu         sync.Mutex
	vConns     map[string]*virtualPacketConn
	vConnsMu   sync.RWMutex
	connecting bool
}

func newConnManager(addr string) *connManager {
	m := &connManager{
		addr:   addr,
		vConns: make(map[string]*virtualPacketConn),
	}
	return m
}

func (m *connManager) connect() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.tcpConn != nil {
		return nil
	}

	conn, err := dialer.DialContext(context.Background(), "tcp", m.addr)
	if err != nil {
		return err
	}
	m.tcpConn = conn

	// Start reading loop for this shared connection
	go m.readLoop(conn)
	return nil
}

func (m *connManager) readLoop(conn net.Conn) {
	defer func() {
		m.mu.Lock()
		if m.tcpConn == conn {
			m.tcpConn = nil
		}
		conn.Close()
		m.mu.Unlock()
	}()

	for {
		var lb [2]byte
		if _, err := io.ReadFull(conn, lb[:]); err != nil {
			return
		}

		totalLen := int(binary.BigEndian.Uint16(lb[:]))
		buf := make([]byte, totalLen)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return
		}

		// Parse udpgw header from server
		// [1 byte type] [4/16 bytes IP] [2 bytes port] [payload]
		addrType := buf[0]
		ipLen := 4
		if addrType == 2 {
			ipLen = 16
		}
		headerLen := 1 + ipLen + 2
		
		dstIP := net.IP(buf[1 : 1+ipLen])
		dstPort := binary.BigEndian.Uint16(buf[1+ipLen : headerLen])
		payload := buf[headerLen:]

		// Find the virtual connection that expects this packet
		key := fmt.Sprintf("%s:%d", dstIP.String(), dstPort)
		m.vConnsMu.RLock()
		vConn, ok := m.vConns[key]
		m.vConnsMu.RUnlock()

		if ok {
			vConn.putPacket(payload, &net.UDPAddr{IP: dstIP, Port: int(dstPort)})
		}
	}
}

func (m *connManager) send(b []byte) error {
	if err := m.connect(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	_, err := m.tcpConn.Write(b)
	return err
}

func (m *connManager) NewVirtualConn(metadata *M.Metadata) *virtualPacketConn {
	key := fmt.Sprintf("%s:%d", metadata.DstIP.String(), metadata.DstPort)
	vc := &virtualPacketConn{
		manager:  m,
		metadata: metadata,
		key:      key,
		ch:       make(chan packet, 100),
	}
	m.vConnsMu.Lock()
	m.vConns[key] = vc
	m.vConnsMu.Unlock()
	return vc
}

type packet struct {
	data []byte
	addr net.Addr
}

type virtualPacketConn struct {
	manager  *connManager
	metadata *M.Metadata
	key      string
	ch       chan packet
	closed   bool
}

func (v *virtualPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	// BadVPN Header
	ip := v.metadata.DstIP.AsSlice()
	addrType := byte(1)
	if len(ip) == 16 {
		addrType = 2
	}

	headerLen := 2 + 1 + len(ip) + 2
	totalLen := headerLen + len(b)
	buf := make([]byte, totalLen)
	
	binary.BigEndian.PutUint16(buf[0:2], uint16(totalLen-2))
	buf[2] = addrType
	copy(buf[3:3+len(ip)], ip)
	binary.BigEndian.PutUint16(buf[3+len(ip):headerLen], uint16(v.metadata.DstPort))
	copy(buf[headerLen:], b)

	if err := v.manager.send(buf); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (v *virtualPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	select {
	case p := <-v.ch:
		n := copy(b, p.data)
		return n, p.addr, nil
	case <-time.After(30 * time.Second):
		return 0, nil, fmt.Errorf("read timeout")
	}
}

func (v *virtualPacketConn) putPacket(data []byte, addr net.Addr) {
	select {
	case v.ch <- packet{data: data, addr: addr}:
	default:
		// Drop if buffer full
	}
}

func (v *virtualPacketConn) Close() error {
	v.manager.vConnsMu.Lock()
	delete(v.manager.vConns, v.key)
	v.manager.vConnsMu.Unlock()
	v.closed = true
	return nil
}

func (v *virtualPacketConn) LocalAddr() net.Addr { return &net.UDPAddr{IP: net.IPv4zero, Port: 0} }
func (v *virtualPacketConn) SetDeadline(t time.Time) error      { return nil }
func (v *virtualPacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (v *virtualPacketConn) SetWriteDeadline(t time.Time) error { return nil }

func Parse(u *url.URL) (proxy.Proxy, error) {
	return New(u.Host), nil
}