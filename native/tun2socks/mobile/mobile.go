package mobile

import (
	"runtime/debug"
	"time"

	"github.com/xjasonlyu/tun2socks/v2/engine"
	"github.com/xjasonlyu/tun2socks/v2/log"
	_ "github.com/xjasonlyu/tun2socks/v2/dns"
	_ "github.com/xjasonlyu/tun2socks/v2/proxy/split"
	_ "github.com/xjasonlyu/tun2socks/v2/proxy/udpgw"
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
	return engine.Run()
}

// Stop stops the tun2socks engine.
func Stop() {
	engine.Stop()
}
