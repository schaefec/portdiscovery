package main

import (
	"crypto/tls"
	"fmt"
)

func main() {

	hostPort := make([]string, 0, 0)

	hostPort = append(hostPort, "localhost:4433")
	hostPort = append(hostPort, "127.0.0.1:4433")

	channel := make(chan tls.ConnectionState)

	for _, hp := range hostPort {

		go dialTLS(hp, channel)

	}
	close(channel)

	for state := range channel {
		for _, cert := range state.PeerCertificates {
			fmt.Println(cert.Subject)
		}
	}
}

func dialTLS(hostport string, ch chan tls.ConnectionState) {
	conn, err := tls.Dial("tcp", hostport, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return
	}
	defer conn.Close()

	conn.Handshake()

	state := conn.ConnectionState()

	ch <- state
}
