package generator

import (
	"crypto/sha256"
	"fmt"
	"strings"

	"github.com/goline/tools"
)

func NewSha256(saltLength int) *Sha256PasswordGenerator {
	return &Sha256PasswordGenerator{
		saltLength: saltLength,
	}
}

type Sha256PasswordGenerator struct {
	saltLength int
}

func (a *Sha256PasswordGenerator) Generate(password string) (string, string) {
	salt := tools.Random(a.saltLength)
	hasher := sha256.New()
	hasher.Write([]byte(password))
	hasher.Write([]byte(salt))
	return fmt.Sprintf("%x", hasher.Sum(nil)), salt
}

func (a *Sha256PasswordGenerator) Verify(password string, salt string, hashed_password string) bool {
	hasher := sha256.New()
	hasher.Write([]byte(password))
	hasher.Write([]byte(salt))

	if strings.Compare(fmt.Sprintf("%x", hasher.Sum(nil)), hashed_password) == 0 {
		return true
	}

	return false
}
