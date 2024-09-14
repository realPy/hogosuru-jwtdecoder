package hs512

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"errors"
)

func CheckHS512(msg []byte, sig []byte, key []byte) error {

	hmac := hmac.New(sha512.New, []byte(key))
	hmac.Write(msg)
	bs := hmac.Sum(nil)
	if !bytes.Equal(bs, sig) {
		return errors.New("signature not matched")
	}
	return nil
}
