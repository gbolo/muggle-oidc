package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/spf13/viper"
)

// these are the only fields we care about for now...
type discoveryResponse struct {
	Issuer           string `json:"issuer"`
	AuthEndpoint     string `json:"authorization_endpoint"`
	TokenEndpoint    string `json:"token_endpoint"`
	UserinfoEndpoint string `json:"userinfo_endpoint"`
	JwksEndpoint     string `json:"jwks_uri"`
	// we use this to determine if we should use pkce
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported"`
}

var (
	discoveryCache    discoveryResponse
	providerJwksCache *jwk.Set
)

func pollDiscovery() (err error) {
	log.Infof("polling OIDC discovery endpoint for configuration")
	discoveryUrl := viper.GetString("oidc.discovery_url")
	resp := doHttpCall("GET", discoveryUrl, nil, nil)
	if resp.err != nil {
		log.Errorf("Failed to call oidc discovery url: %v", resp.err)
		return resp.err
	}
	if resp.StatusCode != http.StatusOK {
		log.Errorf("oidc discovery url returned a non-200 status: %v with body: %s", resp.StatusCode, resp.BodyBytes)
		return fmt.Errorf("oidc discovery url returned a non-200 status: %v", resp.StatusCode)
	}

	err = json.Unmarshal(resp.BodyBytes, &discoveryCache)
	if err != nil {
		return
	}

	err = loadProviderJwks()
	return
}

// loads the provider's jwks endpoint into memory so that we can validate jwt signatures from it
func loadProviderJwks() (err error) {
	log.Debugf("fetching provider's jwks from discovered URL: %s", discoveryCache.JwksEndpoint)
	providerPubKeySet, err = jwk.Fetch(context.TODO(), discoveryCache.JwksEndpoint)
	return
}

// PkceSupported returns true if code challenges are supported
func (d *discoveryResponse) PkceSupported() bool {
	// https://www.iana.org/assignments/oauth-parameters/oauth-parameters.xhtml#pkce-code-challenge-method
	for _, method := range d.CodeChallengeMethodsSupported {
		if method == "plain" || method == "S256" {
			return true
		}
	}
	return false
}

// PkceCodeChallengeMethod returns the best supported method, or an empty string if not supported
// prioritizes S256 over plain
func (d *discoveryResponse) PkceCodeChallengeMethod() (method string) {
	for _, supportedMethod := range d.CodeChallengeMethodsSupported {
		if supportedMethod == "S256" {
			method = supportedMethod
			return
		}
		if supportedMethod == "plain" && method != "S256" {
			method = supportedMethod
		}
	}
	return
}

// PkceCodeChallenge returns the code_challenge, or an empty string if not supported
// prioritizes S256 over plain
func (d *discoveryResponse) PkceCodeChallenge() (codeChallenge string) {
	switch d.PkceCodeChallengeMethod() {
	case "S256":
		codeChallenge = codeVerifier.CodeChallengeS256()
	case "plain":
		codeChallenge = codeVerifier.CodeChallengePlain()
	}
	return
}

// PkceCodeVerifier returns the code_verifier, or an empty string if not supported
func (d *discoveryResponse) PkceCodeVerifier() (cv string) {
	if d.PkceSupported() {
		cv = codeVerifier.String()
	}
	return
}
