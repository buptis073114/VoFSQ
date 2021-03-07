package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"
)

//TCP monitoring used by client
func clientTcpListen() {
	listen, err := net.Listen("tcp", clientAddr)
	if err != nil {
		log.Panic(err)
	}
	defer listen.Close()

	for {
		conn, err := listen.Accept()
		if err != nil {
			log.Panic(err)
		}
		b, err := ioutil.ReadAll(conn)
		if err != nil {
			log.Panic(err)
		}
		fmt.Println(string(b))
	}

}

//TCP listenning used by nodes
func (p *pbft) tcpListen() {
	listen, err := net.Listen("tcp", p.node.addr)
	if err != nil {
		log.Panic(err)
	}
	fmt.Printf("The node starts listening, address:%s\n", p.node.addr)
	defer listen.Close()

	for {
		conn, err := listen.Accept()
		if err != nil {
			log.Panic(err)
		}
		b, err := ioutil.ReadAll(conn)
		if err != nil {
			log.Panic(err)
		}
		p.handleRequest(b)
	}

}

//Sending messages using TCP
func tcpDial(context []byte, addr string) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		log.Println("connect error", err)
		return
	}

	_, err = conn.Write(context)
	if err != nil {
		log.Fatal(err)
	}
	conn.Close()
}
