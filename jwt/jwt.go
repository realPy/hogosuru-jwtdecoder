package jwt

import (
	"encoding/base64"
	"errors"
	"strings"
)

func CheckJWTParts(token string) ([][]byte, []error) {

	decodeparts := [][]byte{}
	errorsret := []error{}
	parts := strings.SplitN(token, ".", 3)

	if len(parts) != 3 {

		return decodeparts, []error{errors.New("invalid delimiter jwt")}
	}

	firstdec, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		firstdec = []byte{}
		errorsret = append(errorsret, errors.New("unable to decode first part"))
	}
	decodeparts = append(decodeparts, firstdec)

	seconddec, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		seconddec = []byte{}
		errorsret = append(errorsret, errors.New("unable to decode second part"))
	}
	decodeparts = append(decodeparts, seconddec)

	thirddec, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		thirddec = []byte{}
		errorsret = append(errorsret, errors.New("unable to decode third part"))
	}
	decodeparts = append(decodeparts, thirddec)

	return decodeparts, errorsret
}
