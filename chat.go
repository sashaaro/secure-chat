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
	PayloadMessage *PayloadMessage
	from *Partner
	text string
}

type Session struct {
	partner *Partner

	dh *DiffieHellman // TODO remove
	publickey []byte // TODO remove
	secret []byte // TODO remove
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

		go func() {
			fmt.Printf("Open:\n%p\n", currentSession)
			chat.openSession(currentSession)
		}()

		for {
			if currentSession.publickey != nil {
				break
			}
			//fmt.Printf("%v\n", currentSession)
			if len(chat.sessions) == 1 {
				fmt.Printf("Wait:\n%p\n", chat.sessions[0])
			}
			time.Sleep(5 * time.Second) // TODO
		}
	}

	plaintext := []byte(text)
	payloadMessage := PayloadMessage{}

	h := sha256.New()

	if currentSession.secret == nil {
		z := new(big.Int)
		z.SetBytes(currentSession.publickey)
		fmt.Println("1", currentSession.publickey)
		currentSession.secret = currentSession.dh.generateSecret(z).Bytes()
	}

	h.Write(currentSession.secret)
	encryptedMessage, _ := encrypt(plaintext, h.Sum(nil))

	copy(payloadMessage.Plaintext[:40], encryptedMessage)
	payloadMessage.Size = int8(len(encryptedMessage))

	payload := new(bytes.Buffer)
	err := binary.Write(payload, binary.LittleEndian, payloadMessage)
	if err != nil {
		panic(err)
	}

	// decrypted, _ := decrypt(payloadMessage.Plaintext[:37], h.Sum(nil))

	//fmt.Println(encryptedMessage)
	// fmt.Println(binary.Size(encryptedMessage))
	//fmt.Println("payloadMessage.Plaintext: ", payloadMessage.Plaintext)


	packet := Packet{MsgType: MsgTypeMessage, Version: CurrentVersion}
	copy(packet.Payload[:48], payload.Bytes())

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

			currentSession := chat.sessions[0]

			if currentSession.secret == nil {
				z := new(big.Int)
				z.SetBytes(currentSession.publickey)
				currentSession.secret = currentSession.dh.generateSecret(z).Bytes()
			}

			h := sha256.New()

			fmt.Println("2", currentSession.secret)
			h.Write(currentSession.secret)

			decrypted, e := decrypt([]byte(message.PayloadMessage.Plaintext[:message.PayloadMessage.Size]), h.Sum(nil))
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
	Plaintext [40]byte
	Size int8
	// from
}

func (chat *Chat) openSession(session *Session)  {
	dh := &DiffieHellman{}
	dh.generateParams(16)
	dh.generatePrivateKey(16)
	dh.generatePublic()

	fmt.Printf("Open session for \n%p\n", session)

	chat.sessions = append(chat.sessions, session)
	session.dh = dh

	fmt.Printf("Opened session for \n%p\n", chat.sessions[0])

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
	copy(startHandshakePacket.Payload[:], buf.Bytes()[:48])

	fmt.Printf("Send PayloadExchange to \n%p\n", string(session.partner.Address))
	chat.transport.sendPacket(session.partner.Address, startHandshakePacket)
}

func (chat *Chat) handlePacket(packet *PacketWithAddress) (*Message, error)  {
	if packet.Version > CurrentVersion {
		return nil, fmt.Errorf(fmt.Sprintf("Unsupported version. Only v%v", CurrentVersion))
	}

	switch packet.MsgType {
	case MsgTypeExchangeKey:
		fmt.Printf("Recieve MsgTypeExchangeKey from \n%p\n", string(packet.address))
		chat.exchangeKey(packet.Payload, packet.address)
	case MsgTypeMessage:
		message := chat.receiveMessage(packet.Payload)
		return message, nil
	}


	return nil, nil
}


func (chat *Chat) exchangeKey(payloadBytes [48]byte, address []byte) {
	payloadExchange := &PayloadExchange{}

	err := binary.Read(bytes.NewReader(payloadBytes[:48]), binary.LittleEndian, payloadExchange)

	if err != nil {
		panic(err)
	}


	fmt.Printf("len(chat.sessions) %v\n", len(chat.sessions))
	if len(chat.sessions) > 0 { // TODO resolve by payload
		session := chat.sessions[0]
		session.publickey = payloadExchange.PublicKey[:2]
		fmt.Printf("Set public key to\n%p\n", chat.sessions[0])
	} else {
		session := &Session{}
		session.publickey = payloadExchange.PublicKey[:2]

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

		fmt.Printf("Init sesstion from external \n%p\n", session)
	}
}

func (chat *Chat) receiveMessage(payloadBytes [48]byte) *Message {
	payloadMessage := &PayloadMessage{}
	err := binary.Read(bytes.NewReader(payloadBytes[:48]), binary.LittleEndian, payloadMessage)

	if err != nil {
		panic(err)
	}

	message := &Message{
		PayloadMessage: payloadMessage,
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

	bobMessages := bobChat.readyReceiveMessage()
	aliceMessages := aliceChat.readyReceiveMessage()

	go func() {
		time.Sleep(2 * time.Second)
		bobChat.sendMessage(alice, "Hi Alice!")
		time.Sleep(2 * time.Second)
		aliceChat.sendMessage(bob, "Hi bob.")

		//time.Sleep(2 * time.Second)
		bobChat.sendMessage(alice, "Hi Alice!22")
		// time.Sleep(2 * time.Second)
		aliceChat.sendMessage(bob, "Hi bob.22")
	}()


	go func() {
		for message := range bobMessages {
			fmt.Printf("Message for Bob -> %s: %s\n", message.from.Name, message.text)
		}
	}()

	for message := range aliceMessages {
		fmt.Printf("Message for Alice -> %s: %s\n", message.from.Name, message.text)
	}
}
