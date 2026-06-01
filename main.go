package main

import (
    "encoding/binary"
    "flag"
    "fmt"
    "io"
    "log"
    "net"
    "sync"
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
	header := make([]byte, 2)

	_, err := io.ReadFull(conn, header)
	if err != nil {
		return 0, err
	}

	ver := header[0]
	nMethods := int(header[1])

	if ver != 0x05 {
		return 0, fmt.Errorf("unsupported version")
	}

	methods := make([]byte, nMethods)

	_, err = io.ReadFull(conn, methods)
	if err != nil {
		return 0, err
	}

	selected := byte(0xFF)

	for _, m := range methods {
		if m == 0x00 {
			selected = 0x00
			break
		}

		if m == 0x02 {
			selected = 0x02
		}
	}

	_, err = conn.Write([]byte{0x05, selected})
	if err != nil {
		return 0, err
	}

	if selected == 0xFF {
		return 0, fmt.Errorf("no acceptable methods")
	}

	return selected, nil
}

func authenticateUserPass(conn net.Conn) error {
	header := make([]byte, 2)

	_, err := io.ReadFull(conn, header)
	if err != nil {
		return err
	}

	ver := header[0]
	ulen := int(header[1])

	if ver != 0x01 {
		conn.Write([]byte{0x01, 0x01})
		return fmt.Errorf("invalid auth version")
	}

	username := make([]byte, ulen)
	_, err = io.ReadFull(conn, username)
	if err != nil {
		return err
	}

	passLen := make([]byte, 1)
	_, err = io.ReadFull(conn, passLen)
	if err != nil {
		return err
	}

	password := make([]byte, int(passLen[0]))
	_, err = io.ReadFull(conn, password)
	if err != nil {
		return err
	}

	if string(username) == "testuser" &&
		string(password) == "testpass" {

		_, err = conn.Write([]byte{0x01, 0x00})
		return err
	}

	_, err = conn.Write([]byte{0x01, 0x01})
	if err != nil {
		return err
	}

	return fmt.Errorf("invalid credentials")
}

func handleConnect(conn net.Conn) (net.Conn, error) {

        header := make([]byte, 4)

        _, err := io.ReadFull(conn, header)
        if err != nil {
                return nil, err
        }

        ver := header[0]
        cmd := header[1]
        atyp := header[3]

        if ver != 0x05 {
                return nil, fmt.Errorf("invalid version")
        }

        if cmd != 0x01 {
                conn.Write([]byte{
                        0x05, 0x07, 0x00, 0x01,
                        0, 0, 0, 0, 0, 0,
                })
                return nil, fmt.Errorf("unsupported command")
        }

        var host string

        switch atyp {

        case 0x01: // IPv4

                addr := make([]byte, 4)

                _, err = io.ReadFull(conn, addr)
                if err != nil {
                        return nil, err
                }

                host = net.IP(addr).String()

        case 0x03: // Domain

                length := make([]byte, 1)

                _, err = io.ReadFull(conn, length)
                if err != nil {
                        return nil, err
                }

                domain := make([]byte, int(length[0]))

                _, err = io.ReadFull(conn, domain)
                if err != nil {
                        return nil, err
                }

                host = string(domain)

        default:

                conn.Write([]byte{
                        0x05, 0x08, 0x00, 0x01,
                        0, 0, 0, 0, 0, 0,
                })

                return nil, fmt.Errorf("unsupported address type")
        }

        portBytes := make([]byte, 2)

        _, err = io.ReadFull(conn, portBytes)
        if err != nil {
                return nil, err
        }

        port := binary.BigEndian.Uint16(portBytes)

        targetAddr := fmt.Sprintf("%s:%d", host, port)

        targetConn, err := net.Dial("tcp", targetAddr)

        if err != nil {

                conn.Write([]byte{
                        0x05, 0x05, 0x00, 0x01,
                        0, 0, 0, 0, 0, 0,
                })

                return nil, err
        }

        _, err = conn.Write([]byte{
                0x05, 0x00, 0x00, 0x01,
                0, 0, 0, 0, 0, 0,
        })

        if err != nil {
                targetConn.Close()
                return nil, err
        }

        return targetConn, nil
}

func relay(client net.Conn, target net.Conn) {
	var wg sync.WaitGroup

	wg.Add(2)

	go func() {
		defer wg.Done()

		io.Copy(target, client)

		if tcp, ok := target.(*net.TCPConn); ok {
			tcp.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()

		io.Copy(client, target)

		if tcp, ok := client.(*net.TCPConn); ok {
			tcp.CloseWrite()
		}
	}()

	wg.Wait()
}

func handleConnection(conn net.Conn) {
        defer conn.Close()

        method, err := negotiateAuth(conn)
        if err != nil {
                return
        }

        if method == 0x02 {
                err = authenticateUserPass(conn)
                if err != nil {
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