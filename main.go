package main

import (
	"flag"
	"fmt"
	"log"
	"net"
)

func main() {
	port := flag.Int("port", 1080, "port to listen on")
	flag.Parse()

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("failed to listen on port %d: %v", *port, err)
	}
	defer listener.Close()

	log.Printf("SOCKS5 proxy listening on :%d", *port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}
		go handleConnection(conn)
	}
}
func negotiateAuth(conn net.Conn) (byte, error) {
	return 0, nil
}

func authenticateUserPass(conn net.Conn) error {
	return nil
}

func handleConnect(conn net.Conn) (net.Conn, error) {
	return nil, nil
}

func relay(client net.Conn, target net.Conn) {
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	method, err := negotiateAuth(conn)
	if err != nil {
		return
	}

	if method == 0x02 {
		if err := authenticateUserPass(conn); err != nil {
			return
		}
	}

	targetConn, err := handleConnect(conn)
	if err != nil {
		return
	}
	defer targetConn.Close()

	relay(conn, targetConn)
}
