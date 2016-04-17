package main

import (
	"flag"
	"fmt"

	"../../../mint"
	"log"
)

var addr string
var pinningEnabled bool
var pinningDB string

func main() {
	flag.StringVar(&addr, "addr", "localhost:4430", "port")
	flag.BoolVar(&pinningEnabled, "pinning", false, "ticket pinning enabled")
	flag.StringVar(&pinningDB, "pinningDB", "", "pinning database file (will be created or opened)")
	flag.Parse()

	if pinningEnabled && (pinningDB == "") {
		log.Fatal("For ticket pinning, you must specify a pinning database file")
	}

	config := mint.Config{
		PinningEnabled:pinningEnabled,
		PinningDB:pinningDB,
	}

	if pinningEnabled {
		ps := mint.PinningStore{}
		ps.InitDB(config)
	}

	conn, err := mint.Dial("tcp", addr, &config)

	if err != nil {
		fmt.Println("TLS handshake failed:", err)
		return
	}

	request := "GET / HTTP/1.0\r\n\r\n"
	conn.Write([]byte(request))

	response := ""
	buffer := make([]byte, 1024)
	var read int
	for err == nil {
		read, err = conn.Read(buffer)
		fmt.Println(" ~~ read: ", read)
		response += string(buffer)
	}
	fmt.Println("err:", err)
	fmt.Println("Received from server:")
	fmt.Println(response)
}
