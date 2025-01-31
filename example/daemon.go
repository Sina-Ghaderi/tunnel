package main

import (
	"flag"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"sync"

	"github.com/sina-ghaderi/tunnel"
)

func main() {
	log.SetFlags(0)

	service := flag.String("service", "server", "run as server or client")
	address := flag.String("address", "0.0.0.0:1099", "listen or dial address")
	localip := flag.String("localip", "10.10.1.1/24", "local ip address of tun interface")

	flag.Parse()

	switch *service {
	case "server":
		serverListen(*address, *localip)
	case "client":
		clientDialTo(*address, *localip)
	default:
		log.Println("bad service:", *service)
		flag.Usage()
		os.Exit(1)
	}
}

func clientDialTo(dialAddr string, ip string) {
	log.Println("client: dialling to vpn server:", dialAddr)
	conn, err := net.Dial("tcp", dialAddr)
	if err != nil {
		log.Fatalf("fatal: %v", err)
	}

	tund, err := tunnel.New(tunnel.Config{})
	if err != nil {
		log.Fatalf("fatal: %v", err)
	}

	if err := setIfaceAddress(ip, tund.Name()); err != nil {
		log.Fatalf("fatal: ip command: %v", err)
	}

	if err := setIfaceUP(tund.Name()); err != nil {
		log.Fatalf("fatal: ip command: %v", err)
	}

	log.Printf("tunnel %s is up and running...", tund.Name())

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer tund.Close()
		err := writeToTun(tund, conn)
		if err != nil {
			log.Fatalf("fatal: %v", err)
		}
		wg.Done()
	}()
	go func() {
		defer conn.Close()
		_, err := io.Copy(conn, tund)
		if err != nil {
			log.Fatalf("fatal: %v", err)
		}
		wg.Done()
	}()

	wg.Wait()
}

func serverListen(listenAddr string, ip string) {

	log.Println("server: listening on address:", listenAddr)
	l, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("fatal: %v", err)
	}

	for {
		conn, err := l.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
		}

		// this is a demonstration, for sake of simplicity
		// we don't handle all clients simultaneously
		serverConn(conn, ip)
	}
}

func serverConn(conn net.Conn, ip string) {

	tund, err := tunnel.New(tunnel.Config{})
	if err != nil {
		conn.Close()
		log.Fatalf("fatal: %v", err)
	}

	if err := setIfaceAddress(ip, tund.Name()); err != nil {
		log.Fatalf("fatal: ip command: %v", err)
	}

	if err := setIfaceUP(tund.Name()); err != nil {
		log.Fatalf("fatal: ip command: %v", err)
	}

	log.Printf("tunnel %s is up and running...", tund.Name())

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer tund.Close()
		writeToTun(tund, conn)
		wg.Done()
	}()
	go func() {
		defer conn.Close()
		io.Copy(conn, tund)
		wg.Done()
	}()

	wg.Wait()
}

func setIfaceAddress(ip string, ifname string) error {
	cmd := exec.Command("ip", "addr", "add", ip, "dev", ifname)
	cmd.Stderr = os.Stdout
	return cmd.Run()
}

func setIfaceUP(ifname string) error {
	cmd := exec.Command("ip", "link", "set", ifname, "up")
	cmd.Stderr = os.Stdout
	return cmd.Run()
}

func writeToTun(dst io.Writer, src io.Reader) error {

	// alloc buffer for ip packets:
	// note: using a small buffer diminishes the advantages of
	// GSO and GRO because the number of system calls increases
	buff := make([]byte, 32*1024)
	p_left := 0 // unwritten data position

	for {

		// read from connection
		nr, err := src.Read(buff[p_left:])
		if err != nil {
			return err
		}

		// if there is any data left from the previous write, take it into account
		if p_left > 0 {
			nr += p_left
			p_left = 0
		}

		// write to tun device
		nw, err := dst.Write(buff[:nr])
		if err != nil {
			return err
		}

		// we couldn't write all the data we read
		// the unwritten data will be buffered for the next write call
		if nr > nw {
			// move unwritten data to the head
			p_left = copy(buff, buff[nw:nr])
		}

	}
}
