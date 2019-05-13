package hostscanner

import (
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"time"
)

// Scanner represents a port-scanner on tcp ports.
type Scanner struct {
	WaitGroup *sync.WaitGroup
	States    chan<- tls.ConnectionState
}

// New creates a new scanner
func New(wg *sync.WaitGroup) *Scanner {
	return &Scanner{
		WaitGroup: wg,
		States:    make(chan tls.ConnectionState, 1024),
	}
}

// Enqueue adds an additional hostport to to the list of to be scanned hosts
func (s *Scanner) Enqueue(hostport string) {
	go dialTLSInternal(hostport, s.States, s.WaitGroup)
}

func dialTLSInternal(hostport string, ch chan<- tls.ConnectionState, wg *sync.WaitGroup) {
	defer wg.Done()
	fmt.Println("Connecting to:", hostport)
	conn, err := tls.DialWithDialer(&net.Dialer{
		Timeout: 500 * time.Millisecond,
	}, "tcp", hostport, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		fmt.Println(err)
		return
	}

	defer conn.Close()

	conn.Handshake()

	fmt.Println("Connection to:", hostport, "established")

	state := conn.ConnectionState()

	ch <- state
}
