/*
 * @Author: xlt
 * @Date: 2023-04-12 13:23:03
 * @LastEditors: xlt
 * @LastEditTime: 2023-05-05 18:10:23
 * @FilePath: /socks5/main.go
 * @Description:
 */
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
	log.Println("socks5 start")
	err := socks5Server.Run()
	if err != nil {
		log.Printf("server start error %S", err)
	}
}
