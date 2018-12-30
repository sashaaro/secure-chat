package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"crypto/tls"
)

type Packet struct {
	Version byte
	MsgType byte
	Payload [48]byte
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
	go func() {
		for {
			conn, err := tcp.listener.Accept()
			if err != nil {
				panic(err)
			}

			packet := &Packet{}

			err2 := binary.Read(conn, binary.LittleEndian, packet)
			if err2 == io.EOF {
				continue
			}
			if err2 != nil {
				panic(err)
			}

			packetWithAddress := &PacketWithAddress{}
			packetWithAddress.Packet = *packet
			packetWithAddress.address = []byte(conn.LocalAddr().String())

			channel <- packetWithAddress
		}
	}()

	return channel
}



type TLSTransport struct {
	port string
	conn *tls.Conn
	listener net.Listener
}

func (transport *TLSTransport) sendPacket(address []byte, packet Packet)  {
	conn, err := tls.Dial("tcp", string(address), &tls.Config{
		InsecureSkipVerify: true,
	})

	if err != nil {
		panic(err)
	}

	transport.conn = conn
	e := binary.Write(conn, binary.LittleEndian, packet)
	if e != nil {
		panic(e)
	}
	defer conn.Close()
}

func (transport *TLSTransport) receivePacket() chan *PacketWithAddress {
	if transport.listener == nil {
		cer, err := tls.LoadX509KeyPair("cert.pem", "key.pem")
		if err != nil {
			panic(err)
		}
		config := &tls.Config{Certificates: []tls.Certificate{cer}}
		transport.listener, _ = tls.Listen("tcp", fmt.Sprintf(":%v", transport.port), config)
	}

	var channel = make(chan *PacketWithAddress)
	go func() {
		for {
			conn, err := transport.listener.Accept()
			if err != nil {
				panic(err)
			}

			go func() {
				packet  := transport.handleConn(conn)
				if packet != nil {
					channel <- packet
				}
			}()
		}
	}()

	return channel
}

func (transport *TLSTransport) handleConn(conn net.Conn) *PacketWithAddress {
	packet := &Packet{}

	err2 := binary.Read(conn, binary.LittleEndian, packet)
	if err2 == io.EOF {
		return nil
	}
	if err2 != nil {
		panic(err2)
	}

	packetWithAddress := &PacketWithAddress{}
	packetWithAddress.Packet = *packet
	packetWithAddress.address = []byte(conn.LocalAddr().String())

	return packetWithAddress
}