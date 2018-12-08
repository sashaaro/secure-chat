package main

import (
	"crypto/rand"
	"math/big"
	"crypto/aes"
	"crypto/cipher"
	"io"
	"errors"
)

// https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange#Secrecy_chart
// https://core.telegram.org/api/end-to-end#key-generation
type DiffieHellman struct {
	publicKey *big.Int
	privateKey *big.Int
	base *big.Int
	modulus *big.Int
	secret *big.Int
}


func (dh *DiffieHellman) generateParams(bits int) (base *big.Int, modules *big.Int)  {
	dh.base, _ = rand.Prime(rand.Reader, bits)
	dh.modulus, _ = rand.Prime(rand.Reader, bits)
	return dh.base, dh.modulus
}

func (dh *DiffieHellman) generatePrivateKey(bits int) *big.Int  {
	dh.privateKey, _ = rand.Prime(rand.Reader,16)

	return dh.privateKey
}

func (dh *DiffieHellman) generatePublic() *big.Int  {
	dh.publicKey = dh.base.Exp(dh.base, dh.privateKey, nil).Mod(dh.base, dh.modulus)

	return dh.publicKey
}

func (dh *DiffieHellman) generateSecret(partnerPublicKey *big.Int) *big.Int  {
	secret := partnerPublicKey.Exp(partnerPublicKey, dh.privateKey, nil).Mod(partnerPublicKey, dh.modulus)
	dh.secret = secret

	return dh.secret
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