package hs256

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
)

func CheckHS256(msg []byte, sig []byte, key []byte) error {

	hmac := hmac.New(sha256.New, []byte(key))
	hmac.Write(msg)
	bs := hmac.Sum(nil)
	if !bytes.Equal(bs, sig) {
		return errors.New("signature not matched")
	}

	return nil
}
