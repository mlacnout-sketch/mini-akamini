package mobile

import (
	"net"
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

var (
	currentMTU int = 1500
)

// Start starts the tun2socks engine with the given parameters.
// udpTimeout is in milliseconds.
func Start(proxy, device, loglevel string, mtu int, udpTimeout int64, snb, rcb string, autotune bool) error {
	// Optimization: Set GC target to 20% to keep RAM usage low on mobile devices
	debug.SetGCPercent(20)
	currentMTU = mtu

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
				log.Infof("[Watchdog] Heartbeat Sent (MTU: %d). Stats: RAM=%d MB", currentMTU, getMemUsage())
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
		
		// Dynamic size calculation: MTU - 20 (IP) - 8 (UDP)
		safeSize := currentMTU - 28
		if safeSize <= 0 { safeSize = 1024 }
		
		chunk := make([]byte, safeSize)
		for i := range chunk {
			chunk[i] = byte(i % 256)
		}

		// Calculate how many chunks needed to reach ~500KB
		count := (500 * 1024) / safeSize

		for i := 0; i < count; i++ {
			conn.Write(chunk)
			if i % 10 == 0 {
				time.Sleep(1 * time.Millisecond)
			}
		}
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
