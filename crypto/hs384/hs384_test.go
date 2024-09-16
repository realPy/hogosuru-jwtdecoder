package hs384_test

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/realPy/hogosuru-jwtdecoder/crypto/hs384"
	"github.com/stretchr/testify/require"
)

var (
	jwt = `eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.lETuUUcanbx3jq__KI1XuBoFDenV98HC8OXOB2ehAXm0fNOgcX2kh3272G-5Vijs`
	key = `helloworld`
)

func TestCheckHS256(t *testing.T) {

	t.Run("valid key", func(t *testing.T) {
		v := strings.SplitN(jwt, ".", 3)
		sig, err := base64.RawURLEncoding.DecodeString(v[2])
		require.NoError(t, err)
		require.NoError(t, hs384.CheckHS384([]byte(v[0]+"."+v[1]), sig, []byte(key)))
	})

	t.Run("invalid key", func(t *testing.T) {
		v := strings.SplitN(jwt, ".", 3)
		sig, err := base64.RawURLEncoding.DecodeString(v[2])
		require.NoError(t, err)
		require.EqualError(t, hs384.CheckHS384([]byte(v[0]+"."+v[1]), sig, []byte("key")), "signature not matched")
	})

}
