package modules

import (
	"bytemomo/kraken/internal/modules/mqtt"
	"bytemomo/kraken/internal/modules/rtsp"
	"bytemomo/kraken/internal/modules/telnet"
)

func Init() {
	mqtt.Init()
	rtsp.Init()
	telnet.Init()
}
