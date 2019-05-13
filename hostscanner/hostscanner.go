package hostscanner

import (
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"time"
)

// Scanner represents a port-scanner on tcp ports.
type Scanner interface {
	// Enqueue adds an additional hostport to to the list of to be scanned hosts
	Enqueue(hostport string) error
	// Closes this scanner and waits until all results has been processed
	CloseAndAwaitTermination()
}

type scanner struct {
	waitGroup      *sync.WaitGroup
	states         chan tls.ConnectionState
	done           chan bool
	closeTriggered bool
}

// NewScanner creates a new scanner
func NewScanner(accept func(tls.ConnectionState)) Scanner {
	scanner := &scanner{
		waitGroup:      &sync.WaitGroup{},
		states:         make(chan tls.ConnectionState, 1024),
		done:           make(chan bool),
		closeTriggered: false,
	}

	go consume(scanner.states, scanner.done, accept)

	return scanner
}

func (s *scanner) Enqueue(hostport string) error {
	if s.closeTriggered {
		return fmt.Errorf("Enqueue cannot be called when scanner has been closed already")
	}
	s.waitGroup.Add(1)
	go dialTLSInternal(hostport, s.states, s.waitGroup)

	return nil
}

func (s *scanner) CloseAndAwaitTermination() {
	if s.closeTriggered {
		return
	}

	s.closeTriggered = true

	fmt.Print("Exiting...")
	s.waitGroup.Wait()
	close(s.states)
	<-s.done
	fmt.Println("done!")
}

func consume(ch <-chan tls.ConnectionState, done chan<- bool, accept func(tls.ConnectionState)) {
	for {
		state, more := <-ch
		if more {
			accept(state)
		} else {
			done <- true
		}
	}
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
