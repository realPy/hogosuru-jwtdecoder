package hs512_test

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/realPy/hogosuru-jwtdecoder/crypto/hs512"
	"github.com/stretchr/testify/require"
)

var (
	jwt = `eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.-r6bdKY0sGi6BP8bQ_ooYjZ6ZZOESMbAwPhIwM6am41-Wx4lcpeAgl0PsIl0OFE33IRio64TzrBOxQKEMAwI5w`
	key = `helloworld`
)

func TestCheckHS256(t *testing.T) {

	t.Run("valid key", func(t *testing.T) {
		v := strings.SplitN(jwt, ".", 3)
		sig, err := base64.RawURLEncoding.DecodeString(v[2])
		require.NoError(t, err)
		require.NoError(t, hs512.CheckHS512([]byte(v[0]+"."+v[1]), sig, []byte(key)))
	})

	t.Run("invalid key", func(t *testing.T) {
		v := strings.SplitN(jwt, ".", 3)
		sig, err := base64.RawURLEncoding.DecodeString(v[2])
		require.NoError(t, err)
		require.EqualError(t, hs512.CheckHS512([]byte(v[0]+"."+v[1]), sig, []byte("key")), "signature not matched")
	})

}
