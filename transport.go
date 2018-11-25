package main

import (
	"encoding/binary"
	"net"
	"unsafe"
)

type Packet struct {
	Version byte
	MsgType byte
	Payload [4]byte
}

const packetSize = int(unsafe.Sizeof(Packet{}))

type Transport interface {
	sendPacket(address []byte, packet Packet)
	receivePacket() chan <- Packet
}


type TCPTransport struct {
	conn *net.Conn
	listener *net.Listener
}

func (tcp *TCPTransport) sendPacket(address []byte, packet Packet)  {
	conn, err := net.Dial("tcp", string(address))

	if err != nil {
		panic(err)
	}

	tcp.conn = &conn
	e := binary.Write(conn, binary.LittleEndian, packet)
	if e != nil {
		panic(e)
	}
	conn.Close()
}

func (tcp *TCPTransport) receivePacket() chan <- Packet {
	if tcp.listener == nil {
		listener, err := net.Listen("tcp", ":8081")
		if err != nil {
			panic(err)
		}

		tcp.listener = &listener
	}

	tcp.listener.Accept()


}