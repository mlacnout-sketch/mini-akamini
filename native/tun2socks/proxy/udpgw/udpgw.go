package udpgw

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/url"
	"sync"

	"github.com/xjasonlyu/tun2socks/v2/dialer"
	M "github.com/xjasonlyu/tun2socks/v2/metadata"
	"github.com/xjasonlyu/tun2socks/v2/proxy"
)

func init() {
	proxy.RegisterProtocol("udpgw", Parse)
}

type Udpgw struct {
	addr string
}

func New(addr string) *Udpgw {
	return &Udpgw{addr: addr}
}

func (u *Udpgw) DialContext(ctx context.Context, metadata *M.Metadata) (net.Conn, error) {
	return nil, fmt.Errorf("udpgw does not support TCP")
}

func (u *Udpgw) DialUDP(metadata *M.Metadata) (net.PacketConn, error) {
	conn, err := dialer.DialContext(context.Background(), "tcp", u.addr)
	if err != nil {
		return nil, err
	}
	return newUdpgwConn(conn, metadata), nil
}

type udpgwConn struct {
	net.Conn
	metadata *M.Metadata
	once     sync.Once
}

func newUdpgwConn(c net.Conn, m *M.Metadata) *udpgwConn {
	return &udpgwConn{Conn: c, metadata: m}
}

func (c *udpgwConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	// BadVPN UDPGW Protocol Header:
	// [2 bytes length] [1 byte addr type] [4/16 bytes IP] [2 bytes port] [Payload]
	
	payloadLen := len(b)
	addrType := byte(1) // IPv4
	ip := c.metadata.DstIP.AsSlice()
	if len(ip) == 16 {
		addrType = 2 // IPv6
	}

	headerLen := 2 + 1 + len(ip) + 2
	totalLen := headerLen + payloadLen
	
	buf := make([]byte, totalLen)
	binary.BigEndian.PutUint16(buf[0:2], uint16(totalLen-2))
	buf[2] = addrType
	copy(buf[3:3+len(ip)], ip)
	binary.BigEndian.PutUint16(buf[3+len(ip):headerLen], uint16(c.metadata.DstPort))
	copy(buf[headerLen:], b)

	_, err := c.Conn.Write(buf)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *udpgwConn) ReadFrom(b []byte) (int, net.Addr, error) {
	// Read length header
	var lb [2]byte
	if _, err := io.ReadFull(c.Conn, lb[:]); err != nil {
		return 0, nil, err
	}
	
	totalLen := int(binary.BigEndian.Uint16(lb[:]))
	buf := make([]byte, totalLen)
	if _, err := io.ReadFull(c.Conn, buf); err != nil {
		return 0, nil, err
	}

	// BadVPN response also has addr header, but usually we just need payload
	// for tun2socks context. Header size is same as request.
	ipLen := 4
	if buf[0] == 2 { ipLen = 16 }
	headerLen := 1 + ipLen + 2
	
	payload := buf[headerLen:]
	n := copy(b, payload)
	return n, c.metadata.UDPAddr(), nil
}

func (c *udpgwConn) Close() error {
	return c.Conn.Close()
}

func Parse(u *url.URL) (proxy.Proxy, error) {
	return New(u.Host), nil
}
