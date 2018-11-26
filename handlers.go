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

	fmt.Print(packet.MsgType)
	switch packet.MsgType {
	case MsgTypeExchangeKey:
		exchangeKey(packet.Payload)
	}

	return nil
}

type PayloadExchange struct {
	Base [2]byte
	Modulus [2]byte
	PublicKey [2]byte
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

	copy(payload.Base[:], base.Bytes()[:2])
	copy(payload.Modulus[:], modulus.Bytes()[:2])
	copy(payload.PublicKey[:], dh.publicKey.Bytes()[:2])
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, payload)
	if err != nil {
		panic(err)
	}

	startHandshakePacket := Packet{
		Version: CurrentVersion,
		MsgType: MsgTypeExchangeKey,
	}

	copy(startHandshakePacket.Payload[:], buf.Bytes()[:10])

	fmt.Println("Start", startHandshakePacket)
	transport.sendPacket(session.partner.Address, startHandshakePacket)
}

func exchangeKey(payloadBytes [10]byte) {
	payloadExchange := &PayloadExchange{}
	var payload []byte

	err := binary.Read(bytes.NewReader(payloadBytes[:10]), binary.LittleEndian, payloadExchange)
	fmt.Print(payload)

	if err != nil {
		panic(err)
	}

	fmt.Print(payloadExchange.Modulus)
	fmt.Print(payloadExchange.Base)

	// TODO session.DH.modulus = payloadExchange.Modulus
	// TODO session.DH.base = payloadExchange.Base
}