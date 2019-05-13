package main

import (
	"crypto/tls"
	"fmt"
	"hostscanner"
	"net"
	"sync"
	"time"
)

func main() {

	hostPort := make([]string, 0, 0)

	hostPort = append(hostPort, "localhost:4433")
	hostPort = append(hostPort, "127.0.0.1:4443")

	new(hostscanner.Scanner)

	channel := make(chan tls.ConnectionState, 1024)
	done := make(chan bool)

	var wg sync.WaitGroup
	for _, hp := range hostPort {
		wg.Add(1)
		go dialTLS(hp, channel, &wg)

	}
	go printState(channel, done)

	wg.Wait() // Block until all producers have been terminated.

	close(channel)

	<-done

	fmt.Println("Exiting...")
}

func printState(statechan <-chan tls.ConnectionState, done chan<- bool) {
	for {
		state, more := <-statechan
		if more {
			for _, cert := range state.PeerCertificates {
				fmt.Println(cert.Subject)
			}
		} else {
			done <- true
		}
	}
}

func dialTLS(hostport string, ch chan<- tls.ConnectionState, wg *sync.WaitGroup) {
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
