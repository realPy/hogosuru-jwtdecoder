package rs256_test

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/realPy/hogosuru-jwtdecoder/crypto/rs256"
	"github.com/stretchr/testify/require"
)

var (
	jwt = `eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.NHVaYe26MbtOYhSKkoKYdFVomg4i8ZJd8_-RU8VNbftc4TSMb4bXP3l3YlNWACwyXPGffz5aXHc6lty1Y2t4SWRqGteragsVdZufDn5BlnJl9pdR_kdVFUsra2rWKEofkZeIC4yWytE58sMIihvo9H1ScmmVwBcQP6XETqYd0aSHp1gOa9RdUPDvoXQ5oqygTqVtxaDr6wUFKrKItgBMzWIdNZ6y7O9E0DhEPTbE9rfBo6KTFsHAZnMg4k68CDp2woYIaXbmYTWcvbzIuHO7_37GT79XdIwkm95QJ7hYC9RiwrV7mesbY4PAahERJawntho0my942XheVLmGwLMBkQ`
	key = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo
4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u
+qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyeh
kd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ
0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdg
cKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbc
mwIDAQAB
-----END PUBLIC KEY-----`
)

func TestCheckHS256(t *testing.T) {

	t.Run("valid key", func(t *testing.T) {
		v := strings.SplitN(jwt, ".", 3)
		sig, err := base64.RawURLEncoding.DecodeString(v[2])
		require.NoError(t, err)
		require.NoError(t, rs256.CheckRS256([]byte(v[0]+"."+v[1]), sig, []byte(key)))
	})

	t.Run("invalid key", func(t *testing.T) {
		v := strings.SplitN(jwt, ".", 3)
		sig, err := base64.RawURLEncoding.DecodeString(v[2])
		require.NoError(t, err)
		require.EqualError(t, rs256.CheckRS256([]byte(v[0]+"."+v[1]), sig, []byte("key")), "failed to decode PEM block containing public key")
	})

}
