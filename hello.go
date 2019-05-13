package main

import (
	"crypto/tls"
	"fmt"

	"github.com/schaefec/portdiscovery/hostscanner"
)

func main() {

	t := hostscanner.NewScanner(func(state tls.ConnectionState) {
		for _, cert := range state.PeerCertificates {
			fmt.Println(cert.Subject)
		}
	})

	t.Enqueue("127.0.0.1:4433")
	t.Enqueue("127.0.0.2:4433")
	t.Enqueue("127.0.0.3:4433")
	t.Enqueue("127.0.0.4:4433")
	t.Enqueue("127.0.0.5:4433")
	t.Enqueue("localhost:4433")

	t.CloseAndAwaitTermination()
}
