/*
 * @Author: xlt
 * @Date: 2023-04-12 13:23:03
 * @LastEditors: xlt
 * @LastEditTime: 2023-05-05 18:11:01
 * @FilePath: /socks5/socks5/socks5.go
 * @Description: socks5代理
 */
package socks5

import (
	"fmt"
	"log"
	"net"
)

const Socks5Version = 0x05

type SOCKS5Server struct {
	Ip   string
	Port int
}

//运行
func (s *SOCKS5Server) Run() error {
	address := fmt.Sprintf("%s:%d", s.Ip, s.Port)
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("connection fail from %s:%s", conn.RemoteAddr(), err)
			continue
		}
		//异步处理请求
		go func() {
			defer conn.Close()
			err := handleConnection(conn)
			if err != nil {
				log.Printf("connection handle fail %s:%s", conn.RemoteAddr(), err)
			}
		}()
	}

}

//处理请求
func handleConnection(conn net.Conn) error {
	//协商过程
	err := HadleAuthMessage(conn, MethodUsernamePassword)
	if err != nil {
		return err
	}
	//校验用户名和密码
	err = VerifyUsernamePassword(conn)
	if err != nil {
		log.Printf("validate username password error %s", err)
		return writeMessage(conn, []byte{Socks5Version, 0x01})
	}

	//请求过程与转发数据过程
	err = HandleConnectMessage(conn)
	if err != nil {
		log.Printf("replay err %s", err)
		return err
	}

	return nil
}

//写入消息
func writeMessage(conn net.Conn, message []byte) error {
	_, err := conn.Write(message)
	return err
}
