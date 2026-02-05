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
	currentMTU   int = 1500
	stopWatchdog chan struct{}
)

// Start starts the tun2socks engine with the given parameters.
func Start(proxy, device, loglevel string, mtu int, udpTimeout int64, snb, rcb string, autotune, autoReconnect bool) error {
	// Optimization: Set GC target to 20% to keep RAM usage low on mobile devices
	debug.SetGCPercent(20)
	currentMTU = mtu
	stopWatchdog = make(chan struct{})

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
		failCount := 0
		for {
			select {
			case <-ticker.C:
				// 1. Send Dummy UDP Packet to keep ISP connection alive
				err := sendDummyPacket()
				
				if err != nil {
					failCount++
					if loglevel != "silent" {
						log.Warnf("[Watchdog] Heartbeat Failed (%d/3): %v", failCount, err)
					}
				} else {
					failCount = 0
				}

				// 2. Action if needed
				if autoReconnect && failCount >= 3 {
					log.Errorf("[WATCHDOG] ACTION_RESTART")
					failCount = 0 // Reset after signaling
				}

				// 3. Log status
				if loglevel != "silent" && err == nil {
					log.Infof("[Watchdog] Heartbeat Sent (MTU: %d). Stats: RAM=%d MB", currentMTU, getMemUsage())
				}
			case <-stopWatchdog:
				return
			}
		}
	}()

	return engine.Run()
}

func sendDummyPacket() error {
	// Send to a stable IP (Cloudflare DNS)
	addr, _ := net.ResolveUDPAddr("udp", "1.1.1.1:53")
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	
	// Dynamic size calculation: MTU - 28 (Header IP/UDP)
	safeSize := currentMTU - 28
	if safeSize <= 0 { safeSize = 1024 }
	
	chunk := make([]byte, safeSize)
	for i := range chunk {
		chunk[i] = byte(i % 256)
	}

	// Calculate how many chunks needed to reach ~500KB total
	count := (500 * 1024) / safeSize

	for i := 0; i < count; i++ {
		_, err := conn.Write(chunk)
		if err != nil {
			return err
		}
		// Small micro-sleep to prevent kernel buffer saturation
		if i % 10 == 0 {
			time.Sleep(1 * time.Millisecond)
		}
	}
	return nil
}

func getMemUsage() uint64 {
	var m debug.GCStats
	debug.ReadGCStats(&m)
	// Return approximate heap usage in MB
	return uint64(m.PauseTotal / 1024 / 1024)
}

// Stop stops the tun2socks engine and the Watchdog.
func Stop() {
	if stopWatchdog != nil {
		// Non-blocking close to be safe
		select {
		case <-stopWatchdog:
		default:
			close(stopWatchdog)
		}
		stopWatchdog = nil
	}
	engine.Stop()
}