package hs256_test

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/realPy/hogosuru-jwtdecoder/crypto/hs256"
	"github.com/stretchr/testify/require"
)

var (
	jwt = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.dD_HjcF4ZoXwMj6Ov7q7uDqCZLeNMhOwC52WEGEG7P0`
	key = `helloworld`
)

func TestCheckHS256(t *testing.T) {

	t.Run("valid key", func(t *testing.T) {
		v := strings.SplitN(jwt, ".", 3)
		sig, err := base64.RawURLEncoding.DecodeString(v[2])
		require.NoError(t, err)
		require.NoError(t, hs256.CheckHS256([]byte(v[0]+"."+v[1]), sig, []byte(key)))
	})

	t.Run("invalid key", func(t *testing.T) {
		v := strings.SplitN(jwt, ".", 3)
		sig, err := base64.RawURLEncoding.DecodeString(v[2])
		require.NoError(t, err)
		require.EqualError(t, hs256.CheckHS256([]byte(v[0]+"."+v[1]), sig, []byte("key")), "signature not matched")
	})

}
