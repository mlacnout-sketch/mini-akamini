package udpgw

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xjasonlyu/tun2socks/v2/dialer"
	"github.com/xjasonlyu/tun2socks/v2/log"
	M "github.com/xjasonlyu/tun2socks/v2/metadata"
	"github.com/xjasonlyu/tun2socks/v2/proxy"
)

const (
	commandKeepAlive  = 0
	commandConnect    = 1
	commandData       = 2
	commandDisconnect = 3
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

	return u.manager.NewVirtualConn(metadata)
}

type connManager struct {
	addr       string
	tcpConn    net.Conn
	mu         sync.Mutex
	vConns     map[uint16]*virtualPacketConn
	vConnsMu   sync.RWMutex
	conIDCount uint32
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
			buf := make([]byte, 3)
			binary.BigEndian.PutUint16(buf[0:2], 1) // Length 1
			buf[2] = commandKeepAlive
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

		cmd := buf[0]
		if cmd == commandKeepAlive { continue }
		
		if len(buf) < 3 { continue }
		conID := binary.BigEndian.Uint16(buf[1:3])

		m.vConnsMu.RLock()
		vConn, ok := m.vConns[conID]
		m.vConnsMu.RUnlock()

		if ok {
			if cmd == commandData {
				vConn.putPacket(buf[3:])
			} else if cmd == commandDisconnect {
				vConn.Close()
			}
		}
	}
}

func (m *connManager) send(b []byte) error {
	if err := m.connect(); err != nil { return err }
	m.mu.Lock()
	defer m.mu.Unlock()
	_, err := m.tcpConn.Write(b)
	return err
}

func (m *connManager) NewVirtualConn(metadata *M.Metadata) (*virtualPacketConn, error) {
	id := uint16(atomic.AddUint32(&m.conIDCount, 1) % 65535)
	vc := &virtualPacketConn{
		manager:  m,
		metadata: metadata,
		conID:    id,
		ch:       make(chan []byte, 200),
	}

	m.vConnsMu.Lock()
	m.vConns[id] = vc
	m.vConnsMu.Unlock()

	// Send CONNECT Command
	ip := metadata.DstIP.AsSlice()
	addrType := byte(1) // IPv4
	if len(ip) == 16 { addrType = 2 }

	headerLen := 1 + 2 + 1 + len(ip) + 2
	buf := make([]byte, 2 + headerLen)
	binary.BigEndian.PutUint16(buf[0:2], uint16(headerLen))
	buf[2] = commandConnect
	binary.BigEndian.PutUint16(buf[3:5], id)
	buf[5] = addrType
	copy(buf[6:6+len(ip)], ip)
	binary.BigEndian.PutUint16(buf[6+len(ip):], uint16(metadata.DstPort))

	if err := m.send(buf); err != nil {
		return nil, err
	}

	return vc, nil
}

type virtualPacketConn struct {
	manager  *connManager
	metadata *M.Metadata
	conID    uint16
	ch       chan []byte
	closed   bool
}

func (v *virtualPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if v.closed { return 0, fmt.Errorf("closed") }
	
	headerLen := 1 + 2 + len(b)
	buf := make([]byte, 2 + headerLen)
	binary.BigEndian.PutUint16(buf[0:2], uint16(headerLen))
	buf[2] = commandData
	binary.BigEndian.PutUint16(buf[3:5], v.conID)
	copy(buf[5:], b)

	if err := v.manager.send(buf); err != nil { return 0, err }
	return len(b), nil
}

func (v *virtualPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	select {
	case p := <-v.ch:
		n := copy(b, p)
		return n, v.metadata.UDPAddr(), nil
	case <-time.After(60 * time.Second):
		return 0, nil, fmt.Errorf("read timeout")
	}
}

func (v *virtualPacketConn) putPacket(data []byte) {
	select {
	case v.ch <- data:
	default:
	}
}

func (v *virtualPacketConn) Close() error {
	if v.closed { return nil }
	v.closed = true
	
	// Send DISCONNECT Command
	buf := make([]byte, 5)
	binary.BigEndian.PutUint16(buf[0:2], 3) // Len 3
	buf[2] = commandDisconnect
	binary.BigEndian.PutUint16(buf[3:5], v.conID)
	v.manager.send(buf)

	v.manager.vConnsMu.Lock()
	delete(v.manager.vConns, v.conID)
	v.manager.vConnsMu.Unlock()
	return nil
}

func (v *virtualPacketConn) LocalAddr() net.Addr { return &net.UDPAddr{IP: net.IPv4zero, Port: 0} }
func (v *virtualPacketConn) SetDeadline(t time.Time) error      { return nil }
func (v *virtualPacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (v *virtualPacketConn) SetWriteDeadline(t time.Time) error { return nil }

func Parse(u *url.URL) (proxy.Proxy, error) {
	return New(u.Host), nil
}
