package main

import (
	"crypto/tls"
	"fmt"
	"strconv"

	"github.com/schaefec/portdiscovery/hostscanner"
)

func main() {

	t := hostscanner.NewScanner(func(state tls.ConnectionState) {
		for _, cert := range state.PeerCertificates {
			fmt.Println(cert.Subject, state.CipherSuite)
		}
	})

	for i := 1; i < 1024; i++ {
		t.Enqueue("kube.opsb.rocks:" + strconv.Itoa(i))
	}

	t.CloseAndAwaitTermination()
}
