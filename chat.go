package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
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
	meta *[]byte
}

type Chat struct {
	sessions *[]*Session
	transport Transport
}

func (chat *Chat) sendMessage(partner *Partner, test string)  {
	var currentSession *Session
	for _, session := range *chat.sessions {
		if session.partner == partner {
			currentSession = session
			break
		}
	}

	if currentSession == nil {
		currentSession = &Session{partner: partner}
		openSession(currentSession, chat.transport)
	}
}

func (chat *Chat) readyReceiveMessage() chan *Message {
	channel := make(chan *Message)

	go func() {
		for packet := range chat.transport.receivePacket() {
			handlePacketV1(packet)
			channel <- &Message{text: "First packet", from: &Partner{Name: "From transport"}}
		}

		channel <- &Message{text: "First letters", from: &Partner{Name: "Alex"}}
		time.Sleep(3 * time.Second)
		channel <- &Message{text: "Second letters", from: &Partner{Name: "Ivan"}}

		close(channel)
	}()

	return channel
}

func main()  {
	chat := &Chat{
		transport: &TCPTransport{
			port: "8081",
		},
		sessions: &[]*Session{},
	}
	chanMessages := chat.readyReceiveMessage()

	go func() {
		for message := range chanMessages {
			fmt.Printf("%s: %s\n", message.from.Name, message.text)
		}
	}()

	time.Sleep(3 * time.Second)

	chat2 := &Chat{
		transport: &TCPTransport{
			port: "8082",
		},
		sessions: &[]*Session{},
	}

	partner := &Partner{Name: "Dmitry", Address: []byte("127.0.0.1:8081")}
	chat2.sendMessage(partner, "Hi")

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