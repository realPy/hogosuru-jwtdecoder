package rs256

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"errors"
)

func getPublicKeyFromPayload(payload []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(payload))
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("unable to parse public key: %w", err)
	}

	key, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is not a *rsa.PublicKey")
	}

	return key, nil
}

func verify(msg []byte, sig []byte, pk *rsa.PublicKey) error {

	hash256 := sha256.New()
	hash256.Write(msg)
	hs := hash256.Sum(nil)

	return rsa.VerifyPKCS1v15(pk, crypto.SHA256, hs, sig)
}

func CheckRS256(msg []byte, sig []byte, key []byte) error {
	rsapublic, err := getPublicKeyFromPayload(key)
	if err != nil {
		return err
	}
	return verify(msg, sig, rsapublic)
}
