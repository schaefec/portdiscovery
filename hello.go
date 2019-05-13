package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"time"
)

func main() {

	hostPort := make([]string, 0, 0)

	hostPort = append(hostPort, "kube.opsb.rocks:433")
	hostPort = append(hostPort, "kube.opsb.rocks:5443")

	channel := make(chan tls.ConnectionState, 1024)
	done := make(chan bool)

	for _, hp := range hostPort {
		go dialTLS(hp, channel)
	}
	printState(channel, done)
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

func dialTLS(hostport string, ch chan<- tls.ConnectionState) {
	fmt.Println("Connecting to:", hostport)
	conn, err := tls.DialWithDialer(&net.Dialer{
		Timeout: 500 * time.Millisecond,
	}, "tcp", hostport, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		log.Info("Error while creating connection: ", err)
		return
	}

	defer conn.Close()

	conn.Handshake()

	fmt.Println("Connection to:", hostport, "established")

	state := conn.ConnectionState()

	ch <- state
}
