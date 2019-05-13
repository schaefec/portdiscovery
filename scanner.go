package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"time"
)

type Scanner struct {
	WaitGroup *sync.WaitGroup
	States    chan<- tls.Connection
}

func New(wg *sync.WaitGroup) *Scanner {
	return &Scanner{
		WaitGroup: wg,
		States:    make(chan tls.ConnectionState, 1024),
	}
}

func (s *Scanner) Enqueue(hostport string) {
	go dialTLS(hostport, s.States)
}

func dialTLS(hostport string, ch chan<- tls.ConnectionState) {
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
