package main

import (
	"fmt"
	"strconv"

	"github.com/schaefec/portdiscovery/hostscanner"
)

func main() {

	t := hostscanner.NewScanner(func(state hostscanner.ScanResult) {
		for _, cert := range state.GetTLSConnectionState().PeerCertificates {
			fmt.Println(cert.Subject)
		}
	})

	for i := 1; i < 1024; i++ {
		t.Enqueue("localhost:" + strconv.Itoa(i))
	}

	t.CloseAndAwaitTermination()
}
