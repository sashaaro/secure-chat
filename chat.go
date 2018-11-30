package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"
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

	modulus [2]byte // TODO remove
	base [2]byte // TODO remove
	publickey [2]byte // TODO remove
	// meta *[]byte
}


type Chat interface {
	readyReceiveMessage() chan *Message
	sendMessage(message *Message)
}

type TransportChat struct {
	sessions *[]*Session
	transport Transport
}

func (chat *TransportChat) sendMessage(partner *Partner, test string)  {
	var currentSession *Session
	for _, session := range *chat.sessions {
		if session.partner == partner {
			currentSession = session
			break
		}
	}

	if currentSession == nil {
		currentSession = &Session{partner: partner}
		chat.openSession(currentSession)
		sessions := append(*chat.sessions, currentSession)
		chat.sessions = &sessions
	}

	plaintext := []byte(test)
	payloadMessage := PayloadMessage{}
	copy(payloadMessage.Plaintext[:10], plaintext[:10])

	payload := new(bytes.Buffer)
	err := binary.Write(payload, binary.LittleEndian, payloadMessage)
	if err != nil {
		panic(err)
	}

	payloadBytes := payload.Bytes()

	packet := &Packet{MsgType:MsgTypeMessage, Version: CurrentVersion}
	copy(packet.Payload[:10], payloadBytes)

	fmt.Printf("Send message packet\n")
	chat.transport.sendPacket(partner.Address, *packet)
}

func (chat *TransportChat) readyReceiveMessage() chan *Message {
	channel := make(chan *Message)

	go func() {
		for packet := range chat.transport.receivePacket() {
			message, err := chat.handlePacket(packet)
			if err != nil {
				panic(err)
			}
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

func (chat *TransportChat) openSession(session *Session)  {

	dh := &DiffieHellman{}

	dh.generateParams(16)
	dh.generatePrivateKey(16)
	dh.generatePublic()

	payload := &PayloadExchange{}

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

	fmt.Printf("Open session\n")
	chat.transport.sendPacket(session.partner.Address, startHandshakePacket)
}

func (chat *TransportChat) sendKey()  {

}

func (chat *TransportChat) handlePacket(packet *Packet) (*Message, error)  {
	if packet.Version > CurrentVersion {
		return nil, fmt.Errorf(fmt.Sprintf("Unsupported version. Only v%v", CurrentVersion))
	}

	fmt.Printf("Receive packet msg type %v\n", packet.MsgType)
	switch packet.MsgType {
	case MsgTypeExchangeKey:
		chat.exchangeKey(packet.Payload)
	case MsgTypeMessage:
		message := chat.receiveMessage(packet.Payload)
		return message, nil
	}


	return nil, nil
}


func (chat *TransportChat) exchangeKey(payloadBytes [10]byte) {
	payloadExchange := &PayloadExchange{}

	err := binary.Read(bytes.NewReader(payloadBytes[:10]), binary.LittleEndian, payloadExchange)

	if err != nil {
		panic(err)
	}

	session := (*chat.sessions)[0] // TODO resolve sender

	session.modulus = payloadExchange.Modulus
	session.base = payloadExchange.Base
	session.publickey = payloadExchange.PublicKey

	dh := &DiffieHellman{}
	dh.base.SetBytes(session.base[:])
	dh.modulus.SetBytes(session.modulus[:])
	dh.generatePrivateKey(16)
	dh.generatePublic()
}

func (chat *TransportChat) receiveMessage(payloadBytes [10]byte) *Message {
	payloadMessage := &PayloadMessage{}
	var payload []byte

	err := binary.Read(bytes.NewReader(payloadBytes[:10]), binary.LittleEndian, payloadMessage)
	fmt.Print(payload)

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

	aliceChat := &TransportChat{
		transport: &TCPTransport{
			port: "8781",
		},
		sessions: &[]*Session{},
	}
	bobChat := &TransportChat{
		transport: &TCPTransport{
			port: "8782",
		},
		sessions: &[]*Session{},
	}

	go func() {
		bobMessages := bobChat.readyReceiveMessage()
		for message := range bobMessages {
			fmt.Printf("Message for Bob -> %s: %s\n", message.from.Name, message.text)
		}
	}()

	go func() {
		time.Sleep(3 * time.Second)
		bobChat.sendMessage(alice, "Hi Alice!")
		time.Sleep(1 * time.Second)
		aliceChat.sendMessage(bob, "Hi bob.")
	}()

	aliceMessages := aliceChat.readyReceiveMessage()
	for message := range aliceMessages {
		fmt.Printf("Message fro Alice -> %s: %s\n", message.from.Name, message.text)
	}
}



// https://astaxie.gitbooks.io/build-web-application-with-golang/en/09.6.html
func encrypt(plaintext []byte, key []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}