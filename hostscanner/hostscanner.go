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

// ScanResult holds the result of the scans
type ScanResult interface {
	// Get tls.Coonnection state
	GetTLSConnectionState() tls.ConnectionState
}

type scanner struct {
	waitGroup            *sync.WaitGroup
	results              chan ScanResult
	done                 chan bool
	closeTriggered       bool
	maxParallelSemaphore chan struct{}
}

type scanResult struct {
	tlsConnectionState tls.ConnectionState
}

// NewScanner creates a new scanner
func NewScanner(accept func(ScanResult)) Scanner {
	scanner := &scanner{
		waitGroup:            &sync.WaitGroup{},
		results:              make(chan ScanResult, 1024),
		done:                 make(chan bool),
		closeTriggered:       false,
		maxParallelSemaphore: make(chan struct{}, 1024),
	}

	go consume(scanner.results, scanner.done, accept)

	return scanner
}

func (r scanResult) GetTLSConnectionState() tls.ConnectionState {
	return r.tlsConnectionState
}

func (s *scanner) Enqueue(hostport string) error {
	if s.closeTriggered {
		return fmt.Errorf("Enqueue cannot be called when scanner has been closed already")
	}
	s.waitGroup.Add(1)
	go dialTLS(hostport, s.results, s.waitGroup, s.maxParallelSemaphore)

	return nil
}

func (s *scanner) CloseAndAwaitTermination() {
	if s.closeTriggered {
		return
	}

	s.closeTriggered = true

	fmt.Print("Exiting...")
	s.waitGroup.Wait()
	close(s.results)
	<-s.done
	fmt.Println("done!")
}

func consume(ch <-chan ScanResult, done chan<- bool, accept func(ScanResult)) {
	for {
		state, more := <-ch
		if more {
			accept(state)
		} else {
			done <- true
		}
	}
}

func dialTLS(hostport string, ch chan<- ScanResult, wg *sync.WaitGroup, maxParallel chan struct{}) {
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

	ch <- scanResult{
		tlsConnectionState: state,
	}
}
