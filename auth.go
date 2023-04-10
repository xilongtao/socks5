package socks5

import (
	"errors"
	"io"
	"log"
	"net"
)

const MethodNoAuthRequired = 0x00   //无需校验
const MethodGSSAPI = 0x01           //gssapi
const MethodUsernamePassword = 0x02 //用户名密码
const MethodNotAcceptable = 0xff    //无可用方法

type ClientAuthMessage struct {
	Version  byte
	Nmethods byte
	Methods  []byte
}

//获取信息，并根据传递的类型来判断是否可以使用鉴权方法，并回复信息
func HadleAuthMessage(conn net.Conn, authType byte) error {
	message, err := GetClientAuthMessage(conn)
	if err != nil {
		return nil
	}
	var acceptAble bool
	for _, method := range message.Methods {
		if method == authType {
			acceptAble = true
			continue
		}
	}
	//根据结果返回不同的response信息流
	if !acceptAble {
		//写入返回消息
		message := []byte{Socks5Version, MethodNotAcceptable}
		return writeMessage(conn, message)
		//return errors.New("not auth method allowed")
	}
	//写入返回信息
	message2 := []byte{Socks5Version, MethodUsernamePassword}
	return writeMessage(conn, message2)
}

func writeMessage(conn net.Conn, message []byte) error {
	_, err := conn.Write(message)
	return err
}

//解析auth信息
func GetClientAuthMessage(conn net.Conn) (*ClientAuthMessage, error) {
	buf := make([]byte, 2)
	_, err := io.ReadFull(conn, buf)
	if err != nil {
		log.Printf("Read Auth Message Fail %s", err)
		return nil, err
	}
	if buf[0] != Socks5Version {
		log.Printf("Socks Version Error")
		return nil, errors.New("socks version not supported")
	}
	nmethods := buf[1]
	//读取可用的auth方法
	buf = make([]byte, nmethods)
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		log.Printf("Read Auth Methods Fail %s", err)
		return nil, err
	}
	return &ClientAuthMessage{
		Version:  Socks5Version,
		Nmethods: nmethods,
		Methods:  buf,
	}, nil
}
