package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
)

const MsgTypeExchangeKey = 1

const CurrentVersion = 1

func handlePacketV1(packet *Packet) (error)  {
	if packet.Version > CurrentVersion {
		return fmt.Errorf(fmt.Sprintf("Unsupported version. Only v%v", CurrentVersion))
	}

	switch packet.MsgType {
	case MsgTypeExchangeKey:
		exchangeKey(packet.Payload)
	}

	return nil
}

type PayloadExchange struct {
	base [2]byte
	modulus [2]byte
	publicKey [2]byte
}

func openSession(session *Session, transport Transport)  {
	base, _ := rand.Prime(rand.Reader,16)
	modulus, _ := rand.Prime(rand.Reader,16)

	alicePrivateKey, _ := rand.Prime(rand.Reader,16)

	dh := &DHClient{
		privateKey:	alicePrivateKey,
		base: base,
		modulus: modulus,
	}

	dh.generatePublic()

	payload := &PayloadExchange{}

	copy(payload.base[:], base.Bytes()[:2])
	copy(payload.modulus[:], modulus.Bytes()[:2])
	copy(payload.publicKey[:], dh.publicKey.Bytes()[:2])
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, payload)
	if err != nil {
		panic(err)
	}

	startHandshakePacket := Packet{
		Version: CurrentVersion,
		MsgType: MsgTypeExchangeKey,
	}

	copy(startHandshakePacket.Payload[:], buf.Bytes()[:4])

	fmt.Println("Start", startHandshakePacket)
	transport.sendPacket(session.partner.Address, startHandshakePacket)
}

func exchangeKey(request [4]byte) {

}