package main

import (
	"github.com/yaronf/mint"
	"log"
	"net"
	"crypto/x509"
	"os"
	"io/ioutil"
	"encoding/pem"
)

func readConfig() *mint.Config {
	serverName := os.Args[1]
	serverCertFile := os.Args[2]
	serverKeyFile := os.Args[3]
	serverKeyBytes, err := ioutil.ReadFile(serverKeyFile)
	if err != nil {
		log.Fatalf("Cannot read key: %s", serverKeyFile)
	}
	serverCertBytes, err := ioutil.ReadFile(serverCertFile)
	if err != nil {
		log.Fatalf("Cannot read cert: %s", serverCertFile)
	}
	serverKeyPEM, _ := pem.Decode(serverKeyBytes)
	serverKeyDER := serverKeyPEM.Bytes
	serverCertPEM, _ := pem.Decode(serverCertBytes)
	serverCertDER := serverCertPEM.Bytes
	serverCert, _    := x509.ParseCertificate(serverCertDER)
	serverKey, _    := x509.ParsePKCS1PrivateKey(serverKeyDER)
	certificates := []*mint.Certificate{
		&mint.Certificate{
			Chain:      []*x509.Certificate{serverCert},
			PrivateKey: serverKey,
		},
	}
	config := &mint.Config{
		ServerName: serverName,
		Certificates: certificates,
	}
	return config
}

func main() {

	service := "0.0.0.0:4430"
	if len(os.Args) < 4 || os.Args[0] == "--help"  {
		log.Printf("Usage: %s server-name cert-file private-key-file", os.Args[0])
		os.Exit(1)
	}
	config := readConfig()
	listener, err := mint.Listen("tcp", service, config)
	if err != nil {
		log.Fatalf("server: listen: %s", err)
	}
	log.Print("server: listening")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("server: accept: %s", err)
			break
		}
		defer conn.Close()
		log.Printf("server: accepted from %s", conn.RemoteAddr())
		go handleClient(conn)
	}
}

func handleClient(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 10)
	for {
		log.Print("server: conn: waiting")
		n, err := conn.Read(buf)
		if err != nil {
			if err != nil {
				log.Printf("server: conn: read: %s", err)
			}
			break
		}

		n, err = conn.Write([]byte("hello world"))
		log.Printf("server: conn: wrote %d bytes", n)

		if err != nil {
			log.Printf("server: write: %s", err)
			break
		}
	}
	log.Println("server: conn: closed")
}
