package main

import (
	"crypto/rand"
	"fmt"
	"log"
)

const MsgTypeExchangeKey = 1

func handlePacketV1(packet Packet) (error)  {
	if packet.Version > 1 {
		return fmt.Errorf("Unsupported version. Only v1")
	}

	switch packet.MsgType {
	case MsgTypeExchangeKey:
		exchangeKey(packet.Payload)
	}
}

func startExcahnge(session *Session)  {
	base, _ := rand.Prime(rand.Reader,16)
	modulus, _ := rand.Prime(rand.Reader,16)

	alicePrivateKey, _ := rand.Prime(rand.Reader,16)

	dh := &DHClient{
		privateKey:	alicePrivateKey,
		modulus: modulus,
		base: base,
	}

	dh.generatePublic()

}

func exchangeKey(request [4]byte) {

}