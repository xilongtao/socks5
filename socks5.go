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
	//判断校验方法方法是否可用

	//请求过程

	//转发数据过程
	return nil
}
