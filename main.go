package main

import (
	"fmt"
	"strconv"

	"github.com/schaefec/portdiscovery/hostscanner"
)

func main() {

	t := hostscanner.NewScanner(10000, func(state hostscanner.ScanResult) {
		fmt.Println(state.GetRemoteAddr())
		for _, cert := range state.GetTLSConnectionState().PeerCertificates {
			fmt.Println(cert.Subject)
		}
	})

	for i := 1; i < 65535; i++ {
		t.Enqueue("localhost:" + strconv.Itoa(i))
	}

	t.CloseAndAwaitTermination()
}
