package oidc

import (
	"crypto/sha256"
	"fmt"

	"github.com/gbolo/muggle-oidc/util"
)

// implementation of RFC 7636
// defined: https://tools.ietf.org/html/rfc7636

// **NOTE** since this client can support "S256" method, I will NOT implement "plain"
const codeChallengeMethodName = "S256"

// If the client is capable of using "S256", it MUST use "S256", as
// "S256" is Mandatory To Implement (MTI) on the server.  Clients are
// permitted to use "plain" only if they cannot support "S256" for some
// technical reason and know via out-of-band configuration that the
// server supports "plain".

type pkce struct {
	codeVerifier string
}

// The client first creates a code verifier, "code_verifier", for each
// OAuth 2.0 [RFC6749] Authorization Request, in the following manner:
// code_verifier = high-entropy cryptographic random STRING using the
// unreserved characters [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
// from Section 2.3 of [RFC3986], with a minimum length of 43 characters
// and a maximum length of 128 characters.
func generateCodeVerifier() (*pkce, error) {
	length := util.GenerateRandomNumber(43, 128)
	cv, err := util.GenerateRandomStringURLSafe(length)
	return &pkce{cv}, err
}

func (p *pkce) GetCodeVerifier() string {
	return p.codeVerifier
}

func (p *pkce) GetCodeChallengeMethod() string {
	return codeChallengeMethodName
}

func (p *pkce) GetCodeChallengeS256() string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(p.GetCodeVerifier())))
}
