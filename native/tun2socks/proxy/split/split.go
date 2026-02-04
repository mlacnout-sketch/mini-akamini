package split

import (
	"context"
	"fmt"
	"net"
	"net/url"

	M "github.com/xjasonlyu/tun2socks/v2/metadata"
	"github.com/xjasonlyu/tun2socks/v2/proxy"
	_ "github.com/xjasonlyu/tun2socks/v2/proxy/relay" // Register relay://
	_ "github.com/xjasonlyu/tun2socks/v2/proxy/socks5" // Register socks5://
)

func init() {
	proxy.RegisterProtocol("split", Parse)
}

type SplitProxy struct {
	tcpProxy proxy.Proxy
	udpProxy proxy.Proxy
}

func Parse(u *url.URL) (proxy.Proxy, error) {
	// Format: split://tcp-proxy-host:port?udp=relay://relay-host:port
	tcpTarget := u.Host
	udpTarget := u.Query().Get("udp")

	if tcpTarget == "" || udpTarget == "" {
		return nil, fmt.Errorf("split proxy requires both tcp and udp targets")
	}

	tcpURL, _ := url.Parse(fmt.Sprintf("socks5://%s", tcpTarget))
	tcpP, err := proxy.Parse(tcpURL)
	if err != nil {
		return nil, err
	}

	udpURL, err := url.Parse(udpTarget)
	if err != nil {
		return nil, err
	}
	udpP, err := proxy.Parse(udpURL)
	if err != nil {
		return nil, err
	}

	return &SplitProxy{
		tcpProxy: tcpP,
		udpProxy: udpP,
	}, nil
}

func (s *SplitProxy) DialContext(ctx context.Context, metadata *M.Metadata) (net.Conn, error) {
	// TCP traffic goes to the fast proxy (Hysteria)
	return s.tcpProxy.DialContext(ctx, metadata)
}

func (s *SplitProxy) DialUDP(metadata *M.Metadata) (net.PacketConn, error) {
	// UDP traffic goes to the Relay proxy (similar to udpgw)
	return s.udpProxy.DialUDP(metadata)
}
