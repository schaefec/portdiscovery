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
	waitGroup            *sync.WaitGroup
	states               chan tls.ConnectionState
	done                 chan bool
	closeTriggered       bool
	maxParallelSemaphore chan struct{}
}

// NewScanner creates a new scanner
func NewScanner(accept func(tls.ConnectionState)) Scanner {
	scanner := &scanner{
		waitGroup:            &sync.WaitGroup{},
		states:               make(chan tls.ConnectionState, 1024),
		done:                 make(chan bool),
		closeTriggered:       false,
		maxParallelSemaphore: make(chan struct{}, 1024),
	}

	go consume(scanner.states, scanner.done, accept)

	return scanner
}

func (s *scanner) Enqueue(hostport string) error {
	if s.closeTriggered {
		return fmt.Errorf("Enqueue cannot be called when scanner has been closed already")
	}
	s.waitGroup.Add(1)
	go dialTLS(hostport, s.states, s.waitGroup, s.maxParallelSemaphore)

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

func dialTLS(hostport string, ch chan<- tls.ConnectionState, wg *sync.WaitGroup, maxParallel chan struct{}) {
	// Limit number of parallel connections.
	maxParallel <- struct{}{}
	defer func() {
		<-maxParallel
	}()
	defer wg.Done()

	conn, err := tls.DialWithDialer(&net.Dialer{
		Timeout: 1000 * time.Millisecond,
	}, "tcp", hostport, &tls.Config{
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
