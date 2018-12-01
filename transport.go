package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

type Packet struct {
	Version byte
	MsgType byte
	Payload [10]byte
}

type PacketWithAddress struct {
	address []byte

	Packet
}

type Transport interface {
	sendPacket(address []byte, packet Packet)
	receivePacket() chan *PacketWithAddress
}


type TCPTransport struct {
	port string
	conn *net.Conn
	listener net.Listener
}

func (tcp *TCPTransport) sendPacket(address []byte, packet Packet)  {
	conn, err := net.Dial("tcp", string(address))

	if err != nil {
		panic(err)
	}

	fmt.Printf("Send packet msg type %v. Address %v \n", packet.MsgType, address)

	tcp.conn = &conn
	e := binary.Write(conn, binary.LittleEndian, packet)
	if e != nil {
		panic(e)
	}
	defer conn.Close()
}

func (tcp *TCPTransport) receivePacket() chan *PacketWithAddress {
	if tcp.listener == nil {
		listener, err := net.Listen("tcp", fmt.Sprintf(":%v", tcp.port))
		if err != nil {
			panic(err)
		}

		tcp.listener = listener
	}

	var channel = make(chan *PacketWithAddress)
	conn, err := tcp.listener.Accept()
	if err != nil {
		panic(err)
	}

	go func() {
		for {
			packet := &Packet{}

			err := binary.Read(conn, binary.LittleEndian, packet)
			if err == io.EOF {
				return
			}
			if err != nil {
				panic(err)
			}

			// fmt.Printf("Receive packet %v\n", packet.MsgType)

			packetWithAddress := &PacketWithAddress{}
			packetWithAddress.Packet = *packet
			packetWithAddress.address = []byte(conn.LocalAddr().String())

			channel <- packetWithAddress
		}
	}()

	return channel
}