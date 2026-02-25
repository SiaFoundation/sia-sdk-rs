// Go helper binary for the Rust mux interop tests (mux/tests/interop.rs).
//
// Build:
//
//	cd mux/testutil/go-interop && go build -o interop .
//
// The compiled binary must be at mux/testutil/go-interop/interop — the Rust
// tests locate it via CARGO_MANIFEST_DIR and will fail if it is missing.
// Once built, the Rust test harness spawns it automatically; there is
// nothing else to do.
//
// Modes:
//
//	interop echo-server PORT    — accept one anonymous mux connection, echo all streams
//	interop echo-client ADDR N SIZE — dial anonymous mux, send/verify echo on N streams
package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"strconv"

	"go.sia.tech/mux"
)

func echoServer(port int) error {
	l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer l.Close()

	// Print the actual port (useful when port=0)
	fmt.Printf("READY %d\n", l.Addr().(*net.TCPAddr).Port)

	conn, err := l.Accept()
	if err != nil {
		return fmt.Errorf("accept tcp: %w", err)
	}
	defer conn.Close()

	m, err := mux.AcceptAnonymous(conn)
	if err != nil {
		return fmt.Errorf("accept mux: %w", err)
	}
	defer m.Close()

	// Accept streams and echo until the mux is closed
	for {
		stream, err := m.AcceptStream()
		if err != nil {
			// Mux closed by peer — normal shutdown
			return nil
		}
		go func() {
			defer stream.Close()
			io.Copy(stream, stream)
		}()
	}
}

func echoClient(addr string, numStreams int, msgSize int) error {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("dial tcp: %w", err)
	}
	defer conn.Close()

	m, err := mux.DialAnonymous(conn)
	if err != nil {
		return fmt.Errorf("dial mux: %w", err)
	}
	defer m.Close()

	type result struct {
		streamID int
		err      error
	}
	results := make(chan result, numStreams)

	for i := 0; i < numStreams; i++ {
		stream := m.DialStream()
		go func(id int) {
			defer stream.Close()

			// Build test message
			msg := make([]byte, msgSize)
			for j := range msg {
				msg[j] = byte(id + j)
			}

			// Write
			if _, err := stream.Write(msg); err != nil {
				results <- result{id, fmt.Errorf("write: %w", err)}
				return
			}

			// Read echo back
			buf := make([]byte, msgSize)
			if _, err := io.ReadFull(stream, buf); err != nil {
				results <- result{id, fmt.Errorf("read: %w", err)}
				return
			}

			// Verify
			for j := range msg {
				if buf[j] != msg[j] {
					results <- result{id, fmt.Errorf("byte %d: got %d, want %d", j, buf[j], msg[j])}
					return
				}
			}

			results <- result{id, nil}
		}(i)
	}

	for i := 0; i < numStreams; i++ {
		r := <-results
		if r.err != nil {
			return fmt.Errorf("stream %d: %w", r.streamID, r.err)
		}
	}

	fmt.Println("PASS")
	return nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: interop <echo-server PORT|echo-client ADDR NUM_STREAMS MSG_SIZE>\n")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "echo-server":
		port := 0
		if len(os.Args) > 2 {
			var err error
			port, err = strconv.Atoi(os.Args[2])
			if err != nil {
				fmt.Fprintf(os.Stderr, "invalid port: %s\n", os.Args[2])
				os.Exit(1)
			}
		}
		if err := echoServer(port); err != nil {
			fmt.Fprintf(os.Stderr, "echo-server error: %v\n", err)
			os.Exit(1)
		}

	case "echo-client":
		if len(os.Args) < 5 {
			fmt.Fprintf(os.Stderr, "usage: interop echo-client ADDR NUM_STREAMS MSG_SIZE\n")
			os.Exit(1)
		}
		addr := os.Args[2]
		numStreams, err := strconv.Atoi(os.Args[3])
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid num_streams: %s\n", os.Args[3])
			os.Exit(1)
		}
		msgSize, err := strconv.Atoi(os.Args[4])
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid msg_size: %s\n", os.Args[4])
			os.Exit(1)
		}
		if err := echoClient(addr, numStreams, msgSize); err != nil {
			fmt.Fprintf(os.Stderr, "echo-client error: %v\n", err)
			os.Exit(1)
		}

	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		os.Exit(1)
	}
}
