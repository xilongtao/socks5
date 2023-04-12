package main

import (
	"log"
	"socks5"
)

func main() {
	socks5Server := socks5.SOCKS5Server{
		Ip:   "localhost",
		Port: 9898,
	}
	err := socks5Server.Run()
	if err != nil {
		log.Printf("server start error %S", err)
	}
}
