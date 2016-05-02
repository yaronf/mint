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
var pinningClearAllTickets bool
var pinningClearTicket string

func initPS(db string) {
	if db == "" {
		log.Fatal("For ticket pinning, you must specify a pinning database file")
	}
	config := mint.Config{
		PinningEnabled:true,
		PinningDB:db,
	}
	mint.InitPinningStore(&config)
}

func main() {
	flag.StringVar(&addr, "addr", "localhost:4430", "port")
	flag.BoolVar(&pinningEnabled, "pinning", false, "ticket pinning enabled")
	flag.StringVar(&pinningDB, "pinning-database", "", "pinning database file (will be created or opened)")
	flag.BoolVar(&pinningClearAllTickets, "pinning-clear-all-tickets", false, "clear all pinning tickets")
	flag.StringVar(&pinningClearTicket, "pinning-clear-ticket", "", "clear pinning ticket for <origin>")
	flag.Parse()

	if pinningClearAllTickets {
		initPS(pinningDB)
		mint.ClientCleanup()
		return
	}

	if pinningClearTicket != "" {
		initPS(pinningDB)
		found := mint.DeleteTicket(pinningClearTicket)
		if found {
			fmt.Println("Deleted one or more tickets")
		} else {
			fmt.Println("Could not find any ticket")
		}
		return
	}

	if pinningEnabled && (pinningDB == "") {
		log.Fatal("For ticket pinning, you must specify a pinning database file")
	}

	config := mint.Config{
		PinningEnabled:pinningEnabled,
		PinningDB:pinningDB,
	}

	if pinningEnabled {
		mint.InitPinningStore(&config)
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
