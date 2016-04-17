package main

import (
	"flag"
	"log"
	"net"

	"../../../mint"
	"crypto/x509"
	"crypto/rsa"
	"io/ioutil"
	"encoding/pem"
)

var port string
var serverName, serverKeyFile, serverCertFile string
var pinningEnabled bool
var pinningDB string

func readServerKey(serverKeyFile string) *rsa.PrivateKey {
	serverKeyBytes, err := ioutil.ReadFile(serverKeyFile)
	if err != nil {
		log.Fatalf("Cannot read key: %s", serverKeyFile)
	}
	serverKeyPEM, _ := pem.Decode(serverKeyBytes)
	serverKeyDER := serverKeyPEM.Bytes
	serverKey, err    := x509.ParsePKCS1PrivateKey(serverKeyDER)
	if err != nil {
		log.Fatalf("Cannot parse private key: %s", serverKeyFile)
	}
	return serverKey
}

func readServerCert(serverCertFile string) *x509.Certificate {
	serverCertBytes, err := ioutil.ReadFile(serverCertFile)
	if err != nil {
		log.Fatalf("Cannot read cert: %s", serverCertFile)
	}
	serverCertPEM, _ := pem.Decode(serverCertBytes)
	serverCertDER := serverCertPEM.Bytes
	serverCert, err := x509.ParseCertificate(serverCertDER)
	if err != nil {
		log.Fatalf("Cannot parse cert: %s", serverCertFile)
	}
	return serverCert
}

func main() {
	var config mint.Config

	flag.StringVar(&port, "port", "4430", "port")
	flag.StringVar(&serverName, "servername", "", "server name")
	flag.StringVar(&serverKeyFile, "keyfile", "", "private key file")
	flag.StringVar(&serverCertFile, "certfile", "", "certificate file")
	flag.BoolVar(&pinningEnabled, "pinning", false, "ticket pinning enabled")
	flag.StringVar(&pinningDB, "pinningDB", "", "pinning database file (will be created or opened)")
	flag.Parse()

	if pinningEnabled && (pinningDB == "") {
		log.Fatal("For ticket pinning, you must specify a pinning database file")
	}

	if serverKeyFile == "" || serverCertFile == "" {
		log.Fatal("You must specify a private key file and a certificate file")
	}

	serverKey := readServerKey(serverKeyFile)
	serverCert := readServerCert(serverCertFile)

	certificates := []*mint.Certificate{
		&mint.Certificate{
			Chain:      []*x509.Certificate{serverCert},
			PrivateKey: serverKey,
		},
	}

	config = mint.Config{
		ServerName: serverName,
		Certificates: certificates,
		PinningEnabled:pinningEnabled,
		PinningDB:pinningDB,
	}

	if pinningEnabled {
		mint.InitPinningStore(&config)
	}

	service := "0.0.0.0:" + port
	listener, err := mint.Listen("tcp", service, &config)

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
