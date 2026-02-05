package mobile

import (
	"runtime/debug"
	"time"

	"github.com/xjasonlyu/tun2socks/v2/engine"
	"github.com/xjasonlyu/tun2socks/v2/log"
	_ "github.com/xjasonlyu/tun2socks/v2/dns"
	_ "github.com/xjasonlyu/tun2socks/v2/proxy/lb"
)

type LogHandler interface {
	WriteLog(message string)
}

func SetLogHandler(h LogHandler) {
	if h != nil {
		log.SetHandler(h)
	}
}

// Start starts the tun2socks engine with the given parameters.
// udpTimeout is in milliseconds.
func Start(proxy, device, loglevel string, mtu int, udpTimeout int64, snb, rcb string, autotune bool) error {
	// Optimization: Set GC target to 20% to keep RAM usage low on mobile devices
	debug.SetGCPercent(20)

	key := &engine.Key{
		Proxy:                    proxy,
		Device:                   device,
		LogLevel:                 loglevel,
		MTU:                      mtu,
		UDPTimeout:               time.Duration(udpTimeout) * time.Millisecond,
		TCPSendBufferSize:        snb,
		TCPReceiveBufferSize:     rcb,
		TCPModerateReceiveBuffer: autotune,
	}
	engine.Insert(key)

	// Start Engine Watchdog
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			// 1. Send Dummy UDP Packet to keep ISP connection alive
			sendDummyPacket()

			// 2. Log status
			if loglevel != "silent" {
				log.Infof("[Watchdog] Heartbeat Sent. Stats: RAM=%d MB", getMemUsage())
			}
		}
	}()

	return engine.Run()
}

func sendDummyPacket() {
	// Send to a stable IP (Cloudflare DNS)
	addr, _ := net.ResolveUDPAddr("udp", "1.1.1.1:53")
	conn, err := net.DialUDP("udp", nil, addr)
	if err == nil {
		defer conn.Close()
		// Small 24-byte dummy DNS-like query or just random data
		conn.Write([]byte("ZIVPN-TURBO-KEEP-ALIVE"))
	}
}

func getMemUsage() uint64 {
	var m debug.GCStats
	debug.ReadGCStats(&m)
	return uint64(m.PauseTotal / 1024 / 1024)
}

// Stop stops the tun2socks engine.
func Stop() {
	engine.Stop()
}
