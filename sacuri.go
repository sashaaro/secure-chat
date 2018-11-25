package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"unsafe"
)

type Packet struct {
	Version byte
	MsgType byte
	Payload [4]byte
}

var size = int(unsafe.Sizeof(Packet{}))
// var size = binary.Size(Packet{})

// Diffie-Hellman
// https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange#Secrecy_chart
// https://core.telegram.org/api/end-to-end#key-generation
type SimpleDHClient struct {
	publicKey byte
	privateKey byte
	base byte
	modulus byte
	secret byte
}

func (dh *SimpleDHClient) generatePublic() byte  {
	publicKey := math.Mod(math.Pow(float64(dh.base), float64(dh.privateKey)), float64(dh.modulus))
	dh.publicKey = byte(publicKey)

	return dh.publicKey
}

func (dh *SimpleDHClient) generateSecret(partnerPublicKey byte) byte  {
	secret := math.Mod(math.Pow(float64(partnerPublicKey), float64(dh.privateKey)), float64(dh.modulus))
	dh.secret = byte(secret)

	return dh.secret
}



type DHClient struct {
	publicKey *big.Int
	privateKey *big.Int
	base *big.Int
	modulus *big.Int
	secret *big.Int
}

func (dh *DHClient) generatePublic() *big.Int  {
	publicKey := dh.base.Exp(dh.base, dh.privateKey, nil).Mod(dh.base, dh.modulus)
	dh.publicKey = publicKey

	return dh.publicKey
}

func (dh *DHClient) generateSecret(partnerPublicKey *big.Int) *big.Int  {
	secret := partnerPublicKey.Exp(partnerPublicKey, dh.privateKey, nil).Mod(partnerPublicKey, dh.modulus)
	dh.secret = secret

	return dh.secret
}

func simpleDH() {
	var base byte = 5
	var modulus byte = 23

	alice := &SimpleDHClient{
		privateKey:	6,
		modulus: modulus,
		base: base,
	}
	bob := &SimpleDHClient{
		privateKey: 15,
		modulus: modulus,
		base: base,
	}

	alice.generatePublic()
	bob.generatePublic()

	fmt.Println("Alice public", alice.publicKey)
	fmt.Println("Bob public", bob.publicKey)

	alice.generateSecret(bob.publicKey)
	bob.generateSecret(alice.publicKey)

	fmt.Println("Alice secret", alice.secret)
	fmt.Println("Bob secret", bob.secret)
}

func main()  {
	alicePrivateKey, _ := rand.Prime(rand.Reader,16)
	bobPrivateKey, _ := rand.Prime(rand.Reader,16)

	base, _ := rand.Prime(rand.Reader,16)
	modulus, _ := rand.Prime(rand.Reader,16)

	alice := &DHClient{
		privateKey:	alicePrivateKey,
		modulus: modulus,
		base: base,
	}
	bob := &DHClient{
		privateKey: bobPrivateKey,
		modulus: modulus,
		base: base,
	}

	alice.generatePublic()
	bob.generatePublic()


	alice.generateSecret(bob.publicKey)
	bob.generateSecret(alice.publicKey)

	fmt.Println("Alice secret", alice.secret)
	fmt.Println("Bob secret", bob.secret)


	h := sha256.New()
	h.Write(alice.secret.Bytes())
	// aesKey := alice.secret.Bytes()
	aesKey := h.Sum(nil)

	var plaintext = "Hello!!!!11"


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
	//data[2] = 0x99

	//packet.msgType = 0x22

	/*ee := binary.Write(os.Stdin, binary.LittleEndian, &packet)
	if ee != nil {
		panic(ee)
	}*/
	e := binary.Read(bytes.NewReader(data), binary.LittleEndian, &packet)
	if e != nil {
		panic(e)
	}

	fmt.Print(packet.MsgType)
	// os.Stdout.Write(packet.payload)
	// os.Stdin.Write([]byte{0x033})
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