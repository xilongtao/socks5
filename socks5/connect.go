/*
 * @Author: xlt
 * @Date: 2023-05-05 13:02:14
 * @LastEditors: xlt
 * @LastEditTime: 2023-05-05 18:59:27
 * @FilePath: /socks5/socks5/connect.go
 * @Description:
 */
package socks5

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
)

const CMDTypeConnect = 0x01 //TCP的连接方法

const AtypeIP4 = 0x01    //IP4
const AtypeDomain = 0x02 //域名类型
const AtypeIP6 = 0x03    //IP6

//请求结构体
type ClientConnectMessage struct {
	Version byte
	Cmd     byte
	Atype   byte
	Address string
	Port    int
}

func HandleConnectMessage(conn net.Conn) error {
	buf := make([]byte, 4)
	_, err := io.ReadFull(conn, buf)
	if err != nil {
		fmt.Println("read connect message error")
	}
	//省略版本号的判断了
	//除了TCP连接其他暂不支持
	if buf[1] != CMDTypeConnect {
		log.Printf("not support protocol")
		return errors.New("not support protocol")
	}
	var addr string
	//非域名的请求也暂不支持
	log.Printf("atype is %d", buf[3])
	switch buf[3] {
	case AtypeIP4:
		buf = make([]byte, 4)
		io.ReadFull(conn, buf)
		addr = fmt.Sprintf("%d.%d.%d.%d", buf[0], buf[1], buf[2], buf[3])
	case AtypeDomain:
		//读取域名
		buf = make([]byte, 1)
		io.ReadFull(conn, buf)
		domainString := make([]byte, buf[0])
		io.ReadFull(conn, domainString)
		addr = string(domainString)
	default:
		log.Printf("not support address")
		return errors.New("not support address")
	}

	portString := make([]byte, 2)
	io.ReadFull(conn, portString)
	port := binary.BigEndian.Uint16(portString)

	log.Printf("address is %s, port is %d", addr, port)

	//创建一个远程链接
	destAddress := fmt.Sprintf("%s:%d", addr, port)
	destConn, err := net.Dial("tcp", destAddress)
	if err != nil {
		log.Printf("connect to remote address error %s", err)
		return err
	}
	//告诉客户端已经准备好了；回传的address类型
	_, err = conn.Write([]byte{Socks5Version, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	if err != nil {
		//关闭链接
		destConn.Close()
		log.Printf("write back connect response error %s", err)
		return err
	}
	defer destConn.Close()
	go io.Copy(destConn, conn)
	//转发数据
	io.Copy(conn, destConn)

	return nil
}
