package main

import "math/big"

// Diffie-Hellman
// https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange#Secrecy_chart
// https://core.telegram.org/api/end-to-end#key-generation
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
