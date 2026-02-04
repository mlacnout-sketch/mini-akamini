package lb

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync/atomic"

	M "github.com/xjasonlyu/tun2socks/v2/metadata"
	"github.com/xjasonlyu/tun2socks/v2/proxy"
)

func init() {
	proxy.RegisterProtocol("lb", Parse)
}

type LoadBalancer struct {
	proxies []proxy.Proxy
	counter uint64
}

func Parse(u *url.URL) (proxy.Proxy, error) {
	// Format: lb://127.0.0.1:20080,127.0.0.1:20081?type=socks5
	targets := strings.Split(u.Host, ",")
	proxyType := u.Query().Get("type")
	if proxyType == "" {
		proxyType = "socks5"
	}

	var proxies []proxy.Proxy
	for _, target := range targets {
		proxyURL, err := url.Parse(fmt.Sprintf("%s://%s", proxyType, target))
		if err != nil {
			return nil, err
		}
		p, err := proxy.Parse(proxyURL)
		if err != nil {
			return nil, err
		}
		proxies = append(proxies, p)
	}

	if len(proxies) == 0 {
		return nil, fmt.Errorf("no targets specified for load balancer")
	}

	return &LoadBalancer{
		proxies: proxies,
		counter: 0,
	}, nil
}

func (l *LoadBalancer) DialContext(ctx context.Context, metadata *M.Metadata) (net.Conn, error) {
	idx := atomic.AddUint64(&l.counter, 1) % uint64(len(l.proxies))
	return l.proxies[idx].DialContext(ctx, metadata)
}

func (l *LoadBalancer) DialUDP(metadata *M.Metadata) (net.PacketConn, error) {
	idx := atomic.AddUint64(&l.counter, 1) % uint64(len(l.proxies))
	return l.proxies[idx].DialUDP(metadata)
}