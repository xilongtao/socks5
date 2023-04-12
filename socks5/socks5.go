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
		return nil
	}
	//校验用户名和密码
	err = VerifyUsernamePassword(conn)
	if err != nil {
		log.Printf("validate username password error %s", err)
		return writeMessage(conn, []byte{Socks5Version, 0x01})
	}

	//请求过程

	//转发数据过程
	return nil
}

//报告错误
func reportErr(err error, desc string) error {
	if err != nil {
		log.Printf("%s %s", desc, err)
		return err
	}
	return nil
}

//写入消息
func writeMessage(conn net.Conn, message []byte) error {
	_, err := conn.Write(message)
	return err
}
