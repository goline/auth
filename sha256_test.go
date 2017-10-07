package auth_test

import (
	"github.com/goline/auth"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Sha256Authenticator", func() {
	It("Generate should return hashed password and salt", func() {
		h := auth.NewSha256(8)
		p, s := h.Generate("some_password")
		Expect(len(s)).To(Equal(8))
		Expect(len(p)).To(Equal(64))
	})

	It("Verify should return false/true", func() {
		h := auth.NewSha256(8)
		Expect(h.Verify("some_password", "NKzBFARw", "77a2a2227644a4cb063f16b276fad87e9ef5f78519df8c94ae61418f8ad2a895")).To(BeFalse())
		Expect(h.Verify("some_password", "NKzBFARw", "77a2a2227644a4cb063f16b276fad87e9ef5f78519df8c94ae61418f8ad2a896")).To(BeTrue())
	})
})
