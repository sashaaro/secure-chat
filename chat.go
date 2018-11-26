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
		// chat.openSession(currentSession)
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

	// TODO session.DH.modulus = payloadExchange.Modulus
	// TODO session.DH.base = payloadExchange.Base
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
	chat := &TransportChat{
		transport: &TCPTransport{
			port: "8081",
		},
		sessions: &[]*Session{},
	}

	go func() {

		chat2 := &TransportChat{
			transport: &TCPTransport{
				port: "8082",
			},
			sessions: &[]*Session{},
		}

		chanMessages2 := chat2.readyReceiveMessage()
		for message := range chanMessages2 {
			fmt.Printf("%s: %s\n", message.from.Name, message.text)
		}

		time.Sleep(3 * time.Second)
		
		partner := &Partner{Name: "Dmitry", Address: []byte("127.0.0.1:8081")}
		chat2.sendMessage(partner, "Hi")

		partner2 := &Partner{Name: "Max", Address: []byte("127.0.0.1:8082")}
		chat.sendMessage(partner2, "Max")
	}()

	chanMessages := chat.readyReceiveMessage()
	for message := range chanMessages {
		fmt.Printf("%s: %s\n", message.from.Name, message.text)
	}

	//alice.generateSecret(bob.publicKey)
	//bob.generateSecret(alice.publicKey)

	//fmt.Println("Alice secret", alice.secret)
	//fmt.Println("Bob secret", bob.secret)


	/*h := sha256.New()
	h.Write(alice.secret.Bytes())
	// aesKey := alice.secret.Bytes()
	aesKey := h.Sum(nil)

	var plaintext = "Hello!!!!11 jlfkdslf lksdjf jdsklfj lsdjflk dslfjldasjflk dsjlkfj dksljflksdaj flkjsadlk fjlksajdf kljsdaljf ds" +
		"sdkfljsdalkjf lksdjflk jsdlkfj lksdjflk sdjkflj ldsjflsjdflk jalkfjaekwljr ;lewkf;ldks ;flkadls;kf; ldskf;lsdakf " +
		"sdf sdaf;s adfkjdksljflksajdflkdsjfoidajsfpewiurpoewkjf;ladjsf;lk slf;smv,.mcx.vmv;sadmvc"


	ciphertext, err := encrypt([]byte(plaintext), aesKey)
	if err != nil {
	}
	fmt.Printf("%s => %x\n", plaintext, ciphertext)

	decrypted, err := decrypt(ciphertext, aesKey)
	if err != nil {
	}
	fmt.Printf("%x => %s\n", ciphertext, decrypted)

	packet := Packet{}

	data := make([]byte, size)
	copy(data, []byte{0x01, 0x01, 0x00, 0x01, 0x02})

	e := binary.Read(bytes.NewReader(data), binary.LittleEndian, &packet)
	if e != nil {
		panic(e)
	}

	fmt.Print(packet.MsgType)*/
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