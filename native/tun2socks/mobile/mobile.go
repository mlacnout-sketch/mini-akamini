package mobile

import (
	"net"
	"runtime/debug"
	"strings"
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
// options string format: "autotune=true,reconnect=false"
func Start(proxy, device, loglevel string, mtu int, udpTimeout int64, snb, rcb string, options string) error {
	// Optimization: Set GC target to 20% to keep RAM usage low on mobile devices
	debug.SetGCPercent(20)
	currentMTU = mtu
	stopWatchdog = make(chan struct{})

	// Parse options
	autotune := strings.Contains(options, "autotune=true")
	autoReconnect := strings.Contains(options, "reconnect=true")

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
				err := sendDummyPacket()
				if err != nil {
					failCount++
					if loglevel != "silent" {
						log.Warnf("[Watchdog] Heartbeat Failed (%d/3): %v", failCount, err)
					}
				} else {
					failCount = 0
				}

				if autoReconnect && failCount >= 3 {
					log.Errorf("[WATCHDOG] ACTION_RESTART")
					failCount = 0
				}

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
	addr, _ := net.ResolveUDPAddr("udp", "1.1.1.1:53")
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	
	safeSize := currentMTU - 28
	if safeSize <= 0 { safeSize = 1024 }
	chunk := make([]byte, safeSize)
	for i := range chunk { chunk[i] = byte(i % 256) }

	count := (500 * 1024) / safeSize
	for i := 0; i < count; i++ {
		_, err := conn.Write(chunk)
		if err != nil { return err }
		if i % 10 == 0 { time.Sleep(1 * time.Millisecond) }
	}
	return nil
}

func getMemUsage() uint64 {
	var m debug.GCStats
	debug.ReadGCStats(&m)
	return uint64(m.PauseTotal / 1024 / 1024)
}

func Stop() {
	if stopWatchdog != nil {
		select {
		case <-stopWatchdog:
		default:
			close(stopWatchdog)
		}
		stopWatchdog = nil
	}
	engine.Stop()
}
