package main

import (
	"bytes"
				"encoding/binary"
		"fmt"
		"time"
	"math/big"
	"crypto/sha256"
)


type Partner struct {
	Name string
	Address []byte
}

type Message struct {
	text string
	from *Partner
}

type Session struct {
	partner *Partner

	dh *DiffieHellman // TODO remove
	publickey [2]byte // TODO remove
	// meta *[]byte
}


type IChat interface {
	readyReceiveMessage() chan *Message
	sendMessage(message *Message)
}

type Chat struct {
	sessions []*Session
	transport Transport
}

func (chat *Chat) sendMessage(partner *Partner, text string)  {
	var currentSession *Session

	if len(chat.sessions) > 0 { // TODO
		currentSession = chat.sessions[0]
	}
	/*for _, session := range chat.sessions {
		if session.partner == partner {
			currentSession = session
			break
		}
	}*/

	if currentSession == nil {
		currentSession = &Session{partner: partner}
		chat.openSession(currentSession)
		time.Sleep(3 * time.Second) // TODO
	}

	plaintext := []byte(text)
	payloadMessage := PayloadMessage{}

	h := sha256.New()
	h.Write(currentSession.dh.privateKey.Bytes())

	encryptedMessage, _ := encrypt(plaintext, h.Sum(nil))
	//copy(payloadMessage.Plaintext[:10], plaintext[:10])
	copy(payloadMessage.Plaintext[:10], encryptedMessage[:10])
	//copy(payloadMessage.Plaintext[:10], encryptedMessage[:10])

	payload := new(bytes.Buffer)
	err := binary.Write(payload, binary.LittleEndian, payloadMessage)
	if err != nil {
		panic(err)
	}

	payloadBytes := payload.Bytes()

	packet := Packet{MsgType: MsgTypeMessage, Version: CurrentVersion}
	copy(packet.Payload[:10], payloadBytes)

	chat.transport.sendPacket(partner.Address, packet)
}

func (chat *Chat) readyReceiveMessage() chan *Message {
	channel := make(chan *Message)

	go func() {
		for packet := range chat.transport.receivePacket() {
			message, err := chat.handlePacket(packet)
			if err != nil {
				panic(err)
			}

			if message == nil {
				continue
			}

			h := sha256.New()
			h.Write(chat.sessions[0].dh.privateKey.Bytes())
			fmt.Println(message)
			decrypted, e := decrypt([]byte(message.text), h.Sum(nil))
			if e != nil {
				panic(e)
			}

			message.text = string(decrypted)

			if message != nil {
				message.from = &Partner{Name: "anony"} // TODO
				channel <- message
			}
		}
		close(channel)
	}()

	return channel
}


const CurrentVersion = 1

const MsgTypeExchangeKey = 1
const MsgTypeMessage = 2

type PayloadExchange struct {
	Base [2]byte
	Modulus [2]byte
	PublicKey [2]byte
}

type PayloadMessage struct {
	Plaintext [10]byte
	// from
}

func (chat *Chat) openSession(session *Session)  {
	dh := &DiffieHellman{}
	dh.generateParams(16)
	dh.generatePrivateKey(16)
	dh.generatePublic()

	chat.sessions = append(chat.sessions, session)
	session.dh = dh

	chat.sendKey(session)
}

func (chat *Chat) sendKey(session *Session)  {
	payload := &PayloadExchange{}

	dh := session.dh
	copy(payload.Base[:], dh.base.Bytes()[:2])
	copy(payload.Modulus[:], dh.modulus.Bytes()[:2])
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
	chat.transport.sendPacket(session.partner.Address, startHandshakePacket)
}

func (chat *Chat) handlePacket(packet *PacketWithAddress) (*Message, error)  {
	if packet.Version > CurrentVersion {
		return nil, fmt.Errorf(fmt.Sprintf("Unsupported version. Only v%v", CurrentVersion))
	}

	switch packet.MsgType {
	case MsgTypeExchangeKey:
		chat.exchangeKey(packet.Payload, packet.address)
	case MsgTypeMessage:
		message := chat.receiveMessage(packet.Payload)
		return message, nil
	}


	return nil, nil
}


func (chat *Chat) exchangeKey(payloadBytes [10]byte, address []byte) {
	payloadExchange := &PayloadExchange{}

	err := binary.Read(bytes.NewReader(payloadBytes[:10]), binary.LittleEndian, payloadExchange)

	if err != nil {
		panic(err)
	}

	// fmt.Println("%v", len(chat.sessions))
	if len(chat.sessions) > 0 { // TODO resolve by payload
		session := chat.sessions[0]
		session.publickey = payloadExchange.PublicKey
	} else {
		session := &Session{}
		session.publickey = payloadExchange.PublicKey

		partner := &Partner{Address: address} // todo find from list by address
		session.partner = partner

		dh := &DiffieHellman{}
		session.dh = dh

		dh.base = new(big.Int)
		dh.modulus = new(big.Int)

		dh.base.SetBytes(payloadExchange.Base[:])
		dh.modulus.SetBytes(payloadExchange.Modulus[:])
		dh.generatePrivateKey(16)
		dh.generatePublic()

		chat.sessions = append(chat.sessions, session)
		chat.sendKey(session)
	}
}

func (chat *Chat) receiveMessage(payloadBytes [10]byte) *Message {
	payloadMessage := &PayloadMessage{}
	err := binary.Read(bytes.NewReader(payloadBytes[:10]), binary.LittleEndian, payloadMessage)

	if err != nil {
		panic(err)
	}

	message := &Message{
		text: string(payloadMessage.Plaintext[:10]),
	}

	return message
}

func main()  {
	alice := &Partner{Name: "Alice", Address: []byte("127.0.0.1:8781")}
	bob := &Partner{Name: "Bob", Address: []byte("127.0.0.1:8782")}

	aliceChat := &Chat{
		transport: &TLSTransport{//TCPTransport{
			port: "8781",
		},
		sessions: []*Session{},
	}
	bobChat := &Chat{
		transport: &TLSTransport{
			port: "8782",
		},
		sessions: []*Session{},
	}

	go func() {
		bobMessages := bobChat.readyReceiveMessage()
		for message := range bobMessages {
			fmt.Printf("Message for Bob -> %s: %s\n", message.from.Name, message.text)
		}
	}()

	go func() {
		time.Sleep(2 * time.Second)
		bobChat.sendMessage(alice, "Hi Alice!")
		time.Sleep(2 * time.Second)
		aliceChat.sendMessage(bob, "Hi bob.")

		time.Sleep(2 * time.Second)
		bobChat.sendMessage(alice, "Hi Alice!22")
		time.Sleep(2 * time.Second)
		aliceChat.sendMessage(bob, "Hi bob.22")
	}()

	aliceMessages := aliceChat.readyReceiveMessage()

	for message := range aliceMessages {
		fmt.Printf("Message fro Alice -> %s: %s\n", message.from.Name, message.text)
	}
}
