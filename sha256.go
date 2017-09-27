package auth

import (
	"crypto/sha256"
	"strings"

	"github.com/goline/tools"
)

type Sha256Authenticator struct {
	SaltLength int
}

func (a *Sha256Authenticator) Generate(password string) (string, string) {
	salt := tools.Random(a.SaltLength)
	hasher := sha256.New()
	hasher.Write([]byte(password))
	hasher.Write([]byte(salt))
	return string(hasher.Sum(nil)), salt
}

func (a *Sha256Authenticator) Verify(password string, salt string, hashed_password string) bool {
	hasher := sha256.New()
	hasher.Write([]byte(password))
	hasher.Write([]byte(salt))

	if strings.Compare(string(hasher.Sum(nil)), hashed_password) == 0 {
		return true
	}

	return false
}
