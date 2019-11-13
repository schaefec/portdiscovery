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
	// Get net.Addr of remote host
	GetRemoteAddr() net.Addr
}

type scanner struct {
	waitGroup            *sync.WaitGroup
	results              chan ScanResult
	done                 chan bool
	closeTriggered       bool
	maxParallelSemaphore chan struct{}
	doCipherScan         bool
}

type scanResult struct {
	tlsConnectionState tls.ConnectionState
	connInfo           net.Addr
}

// AllCipherSuites in a array
var AllCipherSuites = map[uint16]string{
	tls.TLS_RSA_WITH_RC4_128_SHA:                "TLS_RSA_WITH_RC4_128_SHA",
	tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:           "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
	tls.TLS_RSA_WITH_AES_128_CBC_SHA:            "TLS_RSA_WITH_AES_128_CBC_SHA",
	tls.TLS_RSA_WITH_AES_256_CBC_SHA:            "TLS_RSA_WITH_AES_256_CBC_SHA",
	tls.TLS_RSA_WITH_AES_128_CBC_SHA256:         "TLS_RSA_WITH_AES_128_CBC_SHA256",
	tls.TLS_RSA_WITH_AES_128_GCM_SHA256:         "TLS_RSA_WITH_AES_128_GCM_SHA256",
	tls.TLS_RSA_WITH_AES_256_GCM_SHA384:         "TLS_RSA_WITH_AES_256_GCM_SHA384",
	tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:        "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
	tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:          "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
	tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:     "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:      "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
	tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:      "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:   "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:   "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:   "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305:    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305",
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305:  "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",
}

// NewScanner creates a new scanner
func NewScanner(maxParallel int, doCipherScan bool, accept func(ScanResult)) Scanner {
	scanner := &scanner{
		waitGroup:            &sync.WaitGroup{},
		results:              make(chan ScanResult, maxParallel),
		done:                 make(chan bool),
		closeTriggered:       false,
		maxParallelSemaphore: make(chan struct{}, maxParallel),
		doCipherScan:         doCipherScan,
	}

	go consume(scanner.results, scanner.done, accept)

	return scanner
}

func (r scanResult) GetTLSConnectionState() tls.ConnectionState {
	return r.tlsConnectionState
}

func (r scanResult) GetRemoteAddr() net.Addr {
	return r.connInfo
}

func (s *scanner) Enqueue(hostport string) error {
	if s.closeTriggered {
		return fmt.Errorf("Enqueue cannot be called when scanner has been closed already")
	}
	s.waitGroup.Add(1)
	go dialTLS(hostport, s.results, s.waitGroup, s.maxParallelSemaphore, s.doCipherScan)

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

func dialTLS(hostport string, ch chan<- ScanResult, wg *sync.WaitGroup, maxParallel chan struct{}, doCipherScan bool) {
	// Limit number of parallel connections.
	maxParallel <- struct{}{}
	defer func() {
		<-maxParallel
	}()
	defer wg.Done()

	scan := func(ciphers []uint16) {
		conn, err := tls.DialWithDialer(&net.Dialer{
			Timeout: 1000 * time.Millisecond,
		}, "tcp", hostport, &tls.Config{
			InsecureSkipVerify: true,
			CipherSuites:       ciphers,
		})
		if err != nil {
			return
		}

		defer conn.Close()

		conn.Handshake()

		state := conn.ConnectionState()

		ch <- scanResult{
			tlsConnectionState: state,
			connInfo:           conn.RemoteAddr(),
		}
	}

	if doCipherScan {
		for c := range AllCipherSuites {
			scan([]uint16{c})
		}
	} else {
		var ciphers []uint16
		scan(ciphers)
	}
}
