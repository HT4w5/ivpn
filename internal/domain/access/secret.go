package access

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

const (
	legacyPasswordLength = 32
)

type Secret string

func (s Secret) String() string {
	return string(s)
}

func GenerateSecret(m Method) (Secret, error) {
	switch m.Category() {
	case CategoryAEAD2022:
		var keyLen int
		switch m {
		case Method2022Blake3AES128GCM:
			keyLen = 16
		case Method2022Blake3AES256GCM:
			fallthrough
		case Method2022Blake3ChaCha20Poly1305:
			keyLen = 32
		}

		bytes := make([]byte, keyLen)
		if _, err := rand.Read(bytes); err != nil {
			return "", err
		}
		return Secret(base64.StdEncoding.EncodeToString(bytes)), nil

	case CategoryAEAD, CategoryStream:
		bytes := make([]byte, legacyPasswordLength)
		if _, err := rand.Read(bytes); err != nil {
			return "", err
		}
		return Secret(hex.EncodeToString(bytes)), nil

	case CategoryNone:
		return "", nil

	default:
		return "", fmt.Errorf("%w: %s", ErrUnsupportedMethod, m)
	}
}
