// Command testturn is a development-only TURN server for exercising the per-session TURN
// credentials end to end. It accepts the same coturn "use-auth-secret" (TURN REST API) usernames
// and passwords that aegis-rc-server mints. Production uses coturn.
//
//	AEGIS_TURN_SECRET=... testturn -listen 127.0.0.1:3478 -relay 127.0.0.1
package main

import (
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"sync/atomic"

	"github.com/pion/turn/v5"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:3478", "UDP listen address")
	relay := flag.String("relay", "127.0.0.1", "relay IP handed to clients")
	flag.Parse()
	secret := os.Getenv("AEGIS_TURN_SECRET")
	if secret == "" {
		log.Fatal("set AEGIS_TURN_SECRET")
	}
	pc, err := net.ListenPacket("udp4", *listen)
	if err != nil {
		log.Fatal(err)
	}
	var ok, bad atomic.Int64
	rest := turn.LongTermTURNRESTAuthHandler(secret, nil)
	s, err := turn.NewServer(turn.ServerConfig{
		Realm: "aegis-rc",
		AuthHandler: func(ra *turn.RequestAttributes) (string, []byte, bool) {
			u, key, good := rest(ra)
			if good {
				log.Printf("turn auth ok user=%s (ok=%d)", ra.Username, ok.Add(1))
			} else {
				log.Printf("turn auth REJECTED user=%s (rejected=%d)", ra.Username, bad.Add(1))
			}
			return u, key, good
		},
		PacketConnConfigs: []turn.PacketConnConfig{{PacketConn: pc,
			RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{RelayAddress: net.ParseIP(*relay), Address: "0.0.0.0"}}},
	})
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("test TURN server on udp %s, relay %s", *listen, *relay)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	<-sig
	_ = s.Close()
}
