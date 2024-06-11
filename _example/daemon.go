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
		nt, err := io.Copy(tund, conn)
		if err != nil {
			log.Fatalf("fatal: %v at: %d", err, nt)
		}
		wg.Done()
	}()
	go func() {
		defer conn.Close()
		nt, err := io.Copy(conn, tund)
		if err != nil {
			log.Fatalf("fatal: %v at: %d", err, nt)
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

		// this is an example we don't handle all clients simultaneously.
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
		io.Copy(tund, conn)
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
