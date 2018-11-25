package main

import (
	"encoding/binary"
	"fmt"
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
	receivePacket() chan *Packet
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

	tcp.conn = &conn
	e := binary.Write(conn, binary.LittleEndian, packet)
	if e != nil {
		panic(e)
	}
	conn.Close()
}

func (tcp *TCPTransport) receivePacket() chan *Packet {
	if tcp.listener == nil {
		listener, err := net.Listen("tcp", fmt.Sprintf(":%v", tcp.port))
		if err != nil {
			panic(err)
		}

		tcp.listener = listener
	}

	var channel = make(chan *Packet)
	conn, err := tcp.listener.Accept()
	if err != nil {
		panic(err)
	}

	go func() {
		// time.Sleep(4 * time.Second)
		// channel <- &Packet{}

		for {
			// will listen for message to process ending in newline (\n)
			// packetBytes, _ := ioutil.ReadAll(conn)
			packet := &Packet{}

			err := binary.Read(conn, binary.LittleEndian, packet)
			if err != nil {
				panic(err)
			}

			// output message received
			fmt.Println("Receive", packet)

			// channel <- packet
		}
	}()

	return channel
}