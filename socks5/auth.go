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
	log.Printf("子协商-授权报文信息是%#v", message)
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

//校验用户名和密码
func VerifyUsernamePassword(conn net.Conn) error {
	buf := make([]byte, 2)
	//读取version和ulength
	_, err := io.ReadFull(conn, buf)
	if err != nil {
		log.Printf("read username and password err %s", err)
		return err
	}
	//读取用户名
	usernameBuf := make([]byte, buf[1])
	_, err = io.ReadFull(conn, usernameBuf)
	if err != nil {
		log.Printf("read username err %s", err)
		return err
	}
	username := string(usernameBuf)
	//读取plength
	passwordLengthBuf := make([]byte, 1)
	_, err = io.ReadFull(conn, passwordLengthBuf)
	if err != nil {
		log.Printf("read passwordLen err %s", err)
		return err
	}
	//读取密码
	passwordBuf := make([]byte, passwordLengthBuf[0])
	_, err = io.ReadFull(conn, passwordBuf)
	if err != nil {
		log.Printf("read password err %s", err)
		return err
	}
	password := string(passwordBuf)
	log.Printf("子协商-授权报文用户名和密码为 username:%s, password:%s", username, password)
	//比较用户名和密码是否正确
	if username != "Test" || password != "Socks5" {
		log.Printf("validate username and password err %s", err)
		return errors.New("invalid username or password")
	}
	log.Printf("子协商-用户名密码验证成功，username & password validate success")
	//返回数据
	successMsg := []byte{Socks5Version, 0x00}
	return writeMessage(conn, successMsg)
}
