package lb

import (
	"context"
	"fmt"
	"hash/crc32"
	"net"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xjasonlyu/tun2socks/v2/dialer"
	"github.com/xjasonlyu/tun2socks/v2/log"
	M "github.com/xjasonlyu/tun2socks/v2/metadata"
	"github.com/xjasonlyu/tun2socks/v2/proxy"
)

func init() {
	proxy.RegisterProtocol("lb", Parse)
}

// Strategy types
const (
	StrategyRoundRobin      = "rr"
	StrategyLeastConnection = "lc"
	StrategyIPHash          = "hash"
)

// Backend represents a single proxy node (Hysteria Core)
type Backend struct {
	proxy       proxy.Proxy
	addr        string // 127.0.0.1:2008x
	alive       bool
	activeConns int64 // Track active connections
	mu          sync.RWMutex
}

func (b *Backend) IsAlive() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.alive
}

func (b *Backend) SetAlive(status bool) {
	b.mu.Lock()
	b.alive = status
	b.mu.Unlock()
}

func (b *Backend) IncConn() {
	atomic.AddInt64(&b.activeConns, 1)
}

func (b *Backend) DecConn() {
	atomic.AddInt64(&b.activeConns, -1)
}

func (b *Backend) Load() int64 {
	return atomic.LoadInt64(&b.activeConns)
}

// LoadBalancer manages the pool of backends
type LoadBalancer struct {
	backends []*Backend
	strategy string
	counter  uint64
}

func Parse(u *url.URL) (proxy.Proxy, error) {
	// Format: lb://127.0.0.1:20080,127.0.0.1:20081?type=socks5&strategy=lc
	targets := strings.Split(u.Host, ",")
	proxyType := u.Query().Get("type")
	if proxyType == "" {
		proxyType = "socks5"
	}
	
	strategy := u.Query().Get("strategy")
	if strategy == "" {
		strategy = StrategyRoundRobin
	}

	var backends []*Backend
	for _, target := range targets {
		proxyURL, err := url.Parse(fmt.Sprintf("%s://%s", proxyType, target))
		if err != nil {
			return nil, err
		}
		p, err := proxy.Parse(proxyURL)
		if err != nil {
			return nil, err
		}
		
		backends = append(backends, &Backend{
			proxy: p,
			addr:  target,
			alive: true, // Optimistic init
		})
	}

	if len(backends) == 0 {
		return nil, fmt.Errorf("no targets specified for load balancer")
	}

	lb := &LoadBalancer{
		backends: backends,
		strategy: strategy,
		counter:  0,
	}

	// Start Background Health Check
	go lb.healthCheckLoop()

	return lb, nil
}

// healthCheckLoop periodically checks if backends are reachable
func (l *LoadBalancer) healthCheckLoop() {
	for {
		for _, b := range l.backends {
			go func(backend *Backend) {
				// Simple TCP check to the proxy local port
				conn, err := dialer.DialContext(context.Background(), "tcp", backend.addr)
				if err != nil {
					if backend.IsAlive() {
						log.Warnf("[LB] Backend %s is DOWN: %v", backend.addr, err)
						backend.SetAlive(false)
					}
				} else {
					conn.Close()
					if !backend.IsAlive() {
						log.Infof("[LB] Backend %s is UP", backend.addr)
						backend.SetAlive(true)
					}
				}
			}(b)
		}
		time.Sleep(5 * time.Second) // Check every 5 seconds
	}
}

// NextBackend selects the best backend based on strategy and health
func (l *LoadBalancer) NextBackend(metadata *M.Metadata) *Backend {
	aliveBackends := make([]*Backend, 0, len(l.backends))
	for _, b := range l.backends {
		if b.IsAlive() {
			aliveBackends = append(aliveBackends, b)
		}
	}

	// If all dead, fallback to all (try luck)
	if len(aliveBackends) == 0 {
		aliveBackends = l.backends
	}

	switch l.strategy {
	case StrategyLeastConnection:
		var best *Backend
		var minConns int64 = -1
		
		for _, b := range aliveBackends {
			conns := b.Load()
			if best == nil || conns < minConns {
				best = b
				minConns = conns
			}
		}
		return best

	case StrategyIPHash:
		// Sticky Session based on DstIP
		hash := crc32.ChecksumIEEE([]byte(metadata.DstIP.String())) 
		idx := hash % uint32(len(aliveBackends))
		return aliveBackends[idx]

	case StrategyRoundRobin:
		fallthrough
	default:
		idx := atomic.AddUint64(&l.counter, 1) % uint64(len(aliveBackends))
		return aliveBackends[idx]
	}
}

func (l *LoadBalancer) DialContext(ctx context.Context, metadata *M.Metadata) (net.Conn, error) {
	backend := l.NextBackend(metadata)
	
	// Track connection for LeastConnection strategy
	backend.IncConn()
	conn, err := backend.proxy.DialContext(ctx, metadata)
	if err != nil {
		backend.DecConn()
		return nil, err
	}

	// Wrap connection to decrement counter on close
	return &trackedConn{Conn: conn, backend: backend}, nil
}

func (l *LoadBalancer) DialUDP(metadata *M.Metadata) (net.PacketConn, error) {
	// UDP is packet-based, connection tracking is approximate.
	// For simplicity, we just pick a backend without tracking load/close for UDP.
	backend := l.NextBackend(metadata)
	return backend.proxy.DialUDP(metadata)
}

// trackedConn wraps net.Conn to decrement LB counter on close
type trackedConn struct {
	net.Conn
	backend *Backend
	once    sync.Once
}

func (c *trackedConn) Close() error {
	c.once.Do(func() {
		c.backend.DecConn()
	})
	return c.Conn.Close()
}
