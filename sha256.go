package auth

import (
	"crypto/sha256"
	"strings"

	"github.com/goline/tools"
	"fmt"
)

func NewSha256(saltLength int) Authenticator {
	return &Sha256Authenticator{
		saltLength: saltLength,
	}
}

type Sha256Authenticator struct {
	saltLength int
}

func (a *Sha256Authenticator) Generate(password string) (string, string) {
	salt := tools.Random(a.saltLength)
	hasher := sha256.New()
	hasher.Write([]byte(password))
	hasher.Write([]byte(salt))
	return fmt.Sprintf("%x", hasher.Sum(nil)), salt
}

func (a *Sha256Authenticator) Verify(password string, salt string, hashed_password string) bool {
	hasher := sha256.New()
	hasher.Write([]byte(password))
	hasher.Write([]byte(salt))

	if strings.Compare(fmt.Sprintf("%x", hasher.Sum(nil)), hashed_password) == 0 {
		return true
	}

	return false
}
