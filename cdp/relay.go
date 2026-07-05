package cdp

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/url"
)

// StartProxyRelay starts a local CONNECT proxy that forwards to an upstream
// authenticated proxy, adding the Proxy-Authorization header. Chrome connects
// to the local relay (no auth); the relay adds auth for the upstream.
// Returns the local proxy URL (http://127.0.0.1:PORT) and a cleanup function.
func StartProxyRelay(upstreamURL string) (string, func(), error) {
	u, err := url.Parse(upstreamURL)
	if err != nil {
		return "", nil, err
	}
	authHeader := ""
	if u.User != nil {
		creds := u.User.String()
		authHeader = "Basic " + base64.StdEncoding.EncodeToString([]byte(creds))
	}
	upstreamAddr := u.Host
	if upstreamAddr == "" {
		return "", nil, fmt.Errorf("no host in upstream proxy URL")
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	addr := ln.Addr().String()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleRelay(conn, upstreamAddr, authHeader)
		}
	}()

	return "http://" + addr, func() { ln.Close() }, nil
}

func handleRelay(clientConn net.Conn, upstreamAddr, authHeader string) {
	defer clientConn.Close()
	br := bufio.NewReader(clientConn)

	// read the CONNECT line from Chrome
	reqLine, err := br.ReadString('\n')
	if err != nil || reqLine == "\r\n" || reqLine == "\n" {
		return
	}
	// consume remaining headers
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}

	// connect to upstream proxy
	upstream, err := net.Dial("tcp", upstreamAddr)
	if err != nil {
		fmt.Fprintf(clientConn, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return
	}
	defer upstream.Close()

	// send CONNECT to upstream with Proxy-Authorization
	if authHeader != "" {
		fmt.Fprintf(upstream, "%sProxy-Authorization: %s\r\n\r\n", reqLine, authHeader)
	} else {
		fmt.Fprintf(upstream, "%s\r\n", reqLine)
	}

	// read upstream's response (expect "HTTP/1.1 200 Connection established")
	ubr := bufio.NewReader(upstream)
	for {
		line, err := ubr.ReadString('\n')
		if err != nil {
			return
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}

	// tell Chrome: connection established
	fmt.Fprintf(clientConn, "HTTP/1.1 200 Connection established\r\n\r\n")

	// relay bytes both ways
	go io.Copy(upstream, br)
	io.Copy(clientConn, ubr)
}
