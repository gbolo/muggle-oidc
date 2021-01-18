package oidc

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"github.com/gbolo/muggle-oidc/util"
	"time"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	cv "github.com/nirasan/go-oauth-pkce-code-verifier"
	"github.com/spf13/viper"
)

var (
	codeVerifier      *cv.CodeVerifier
	signingKeySet     jwk.Set
	pubKeySet         jwk.Set
	providerPubKeySet jwk.Set
)

type jwksJson struct {
	Keys []jwk.Key `json:"keys"`
}

func initJwtSigningKey() {
	// lets generate a bunch of RSA keys so that we can randomly pick one during signing
	signingKeySet = jwk.NewSet()
	pubKeySet = jwk.NewSet()
	for i := 1; i <= 2; i++ {
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			log.Fatalf("failed to generate new RSA private key: %s", err)
		}
		key, err := jwk.New(rsaKey)
		if err != nil {
			log.Fatalf("failed to create jwk key: %s", err)
		}
		keyID := util.GenerateRandomString(12)
		key.Set(jwk.KeyIDKey, keyID)
		key.Set(jwk.KeyUsageKey, jwk.ForSignature)
		key.Set(jwk.AlgorithmKey, jwa.RS256)
		log.Debugf("added generated RSA private key with kid %s to our jwks", keyID)
		signingKeySet.Add(key)
		//signingKeySet.Keys = append(signingKeySet.Keys, key)

		// TODO: we need the pub portion of the keys stored in another jwk.Set for now
		// https://github.com/lestrrat-go/jwx/issues/293
		//pubKey, _ := jwk.New(rsaKey.Public())
		//pubKey.Set(jwk.KeyIDKey, keyID)
		//pubKey.Set(jwk.KeyUsageKey, jwk.ForSignature)
		//pubKey.Set(jwk.AlgorithmKey, jwa.RS256)
		//pubKeySet.Keys = append(pubKeySet.Keys, pubKey)
	}

	// init public jwks
	var err error
	pubKeySet, err = jwk.PublicSetOf(signingKeySet)
	if err != nil {
		log.Fatalf("could not produce a public jwks: %v", err)
	}
	// init pkce
	codeVerifier, err = cv.CreateCodeVerifier()
	if err != nil {
		log.Fatalf("could not init PKCE code verifier: %v", err)
	}
}

func getSigningKey() (key jwk.Key) {
	if signingKeySet.Len() > 0 {
		key, _ = signingKeySet.Get(util.GenerateRandomNumber(0, signingKeySet.Len()-1))
	}
	return
}

func GetPublicJWKS() (encoded []byte) {
	encoded, _ = json.Marshal(pubKeySet)
	return
}

// jwt used during initial auth request
func createRequestJWT(state, nonce, redirectURL string) (jwtString string) {

	token := jwt.New()
	// set claims
	token.Set(jwt.AudienceKey, discoveryCache.Issuer)
	token.Set(jwt.IssuerKey, viper.GetString("oidc.client_id"))
	token.Set(jwt.IssuedAtKey, time.Now().Unix())
	token.Set("code_challenge_method", "S256")
	token.Set("code_challenge", codeVerifier.CodeChallengeS256())
	token.Set("scope", viper.GetString("oidc.scope"))
	token.Set("response_type", "code")
	token.Set("redirect_uri", redirectURL)
	token.Set("state", state)
	token.Set("ui_locales", "en-CA")
	token.Set("nonce", nonce)

	return signJWT(&token)
}

// jwt used during access token request
func createAssertionJWT() (jwtString string) {

	token := jwt.New()
	// set claims
	token.Set(jwt.AudienceKey, discoveryCache.TokenEndpoint)
	token.Set(jwt.SubjectKey, viper.GetString("oidc.client_id"))
	token.Set(jwt.IssuerKey, viper.GetString("oidc.client_id"))
	token.Set(jwt.IssuedAtKey, time.Now().Unix())
	token.Set(jwt.ExpirationKey, time.Now().Add(time.Minute*10).Unix())
	token.Set(jwt.JwtIDKey, util.GenerateRandomString(16))

	return signJWT(&token)
}

func signJWT(token *jwt.Token) string {
	// sign our token. If we cant sign it's fatal cause something terribly wrong...
	signedJwt, err := jwt.Sign(*token, jwa.RS256, getSigningKey())
	if err != nil {
		log.Fatalf("cannot sign token with our key: %v", err)
	}
	return string(signedJwt)
}
