package oidc

import (
	"encoding/json"
	"io/ioutil"
	"strings"
	"time"

	"github.com/gbolo/muggle-oidc/crypto"
	"github.com/gbolo/muggle-oidc/util"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	cv "github.com/nirasan/go-oauth-pkce-code-verifier"
	"github.com/spf13/viper"
)

var (
	// used for code challenges pkce
	codeVerifier *cv.CodeVerifier
	// these are our signing key(s). The pubKeySet is what we share in our jwks endpoint
	signingKeySet jwk.Set
	pubKeySet     jwk.Set
	// used to validate provider jwt (id_token)
	providerPubKeySet jwk.Set
)

func generatePrivateJWKS(count int, keyType string) (signingKeySet jwk.Set) {
	signingKeySet = jwk.NewSet()
	switch strings.ToUpper(keyType) {
	case "RSA":
		n := 0
		for n < count {
			n++
			keyRSA, err := crypto.GenerateRSAKey(2048)
			if err != nil {
				log.Fatalf("failed to generate RSA key: %v", err)
			}
			key, err := jwk.New(keyRSA)
			if err != nil {
				log.Fatalf("failed to create jwk key: %s", err)
			}
			keyID, _ := util.GenerateRandomString(12)
			key.Set(jwk.KeyIDKey, keyID)
			key.Set(jwk.KeyUsageKey, jwk.ForSignature)
			key.Set(jwk.AlgorithmKey, jwa.RS256)
			log.Debugf("added generated RSA private key with kid %s to our jwks", keyID)
			signingKeySet.Add(key)
		}
	case "EC":
		n := 0
		for n < count {
			n++
			keyEC, err := crypto.GenerateECKey("P-256")
			if err != nil {
				log.Fatalf("failed to generate EC key: %v", err)
			}
			key, err := jwk.New(keyEC)
			if err != nil {
				log.Fatalf("failed to create jwk key: %s", err)
			}
			keyID, _ := util.GenerateRandomString(12)
			key.Set(jwk.KeyIDKey, keyID)
			key.Set(jwk.KeyUsageKey, jwk.ForSignature)
			key.Set(jwk.AlgorithmKey, jwa.ES256)
			log.Debugf("added generated EC private key with kid %s to our jwks", keyID)
			signingKeySet.Add(key)
		}
	default:
		log.Fatalf("unsupported key type specified: %s", keyType)
	}

	return
}

func loadPrivateKeyFromDisk(path, keyID, keyAlg string) (signingKeySet jwk.Set) {
	signingKeySet = jwk.NewSet()
	log.Infof("reading in static signing key pem from disk: %v", path)
	keyBytes, err := ioutil.ReadFile(path)
	if err != nil {
		log.Fatalf("could not load static jwt signing key: %v", err)
	}
	keyFromDisk, err := crypto.ParsePrivateKeyPEM(keyBytes)
	if err != nil {
		log.Fatalf("could not parse key file: %v", err)
	}
	key, err := jwk.New(keyFromDisk)
	if err != nil {
		log.Fatalf("failed to create jwk key: %s", err)
	}
	// create a random keyID if one wasn't specified
	if keyID == "" {
		keyID, _ = util.GenerateRandomString(12)
	}

	// validate that the signature algorithm is valid
	var sigAlg jwa.SignatureAlgorithm
	if err = sigAlg.Accept(keyAlg); err != nil {
		log.Fatalf("invalid key algorithm specified %s: %v", keyAlg, err)
	}

	key.Set(jwk.KeyIDKey, keyID)
	key.Set(jwk.KeyUsageKey, jwk.ForSignature)
	key.Set(jwk.AlgorithmKey, sigAlg)
	log.Debugf("added private key with kid %s to our jwks with alg %s", keyID, sigAlg.String())
	signingKeySet.Add(key)

	return
}

func initJwtSigningKey() {

	// private keys are either generated or read from disk
	if viper.GetBool("jwt.signing_key.generate.enabled") {
		keyCount := viper.GetInt("jwt.signing_key.generate.count")
		if keyCount < 1 {
			log.Fatalf("jwt.signing_key.generate.count is less than 1")
		}
		keyType := viper.GetString("jwt.signing_key.generate.key_type")
		signingKeySet = generatePrivateJWKS(keyCount, keyType)
	} else {
		keyFile := viper.GetString("jwt.signing_key.static.path")
		keyAlg := viper.GetString("jwt.signing_key.static.alg")
		signingKeySet = loadPrivateKeyFromDisk(keyFile, viper.GetString("jwt.signing_key.static.id"), keyAlg)
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
	token.Set("scope", viper.GetString("oidc.scope"))
	token.Set("response_type", "code")
	token.Set("redirect_uri", redirectURL)
	token.Set("state", state)
	token.Set("ui_locales", "en-CA")
	token.Set("nonce", nonce)
	// pkce code challenge if supported
	if discoveryCache.PkceSupported() {
		token.Set("code_challenge_method", discoveryCache.PkceCodeChallengeMethod())
		token.Set("code_challenge", discoveryCache.PkceCodeChallenge())
	}

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
	jwtID, _ := util.GenerateRandomString(16)
	token.Set(jwt.JwtIDKey, jwtID)

	return signJWT(&token)
}

func signJWT(token *jwt.Token) string {
	// sign our token. If we cant sign it's fatal cause something terribly wrong...
	signingKey := getSigningKey()
	signatureAlg, err := getSignatureAlgorithm(signingKey.Algorithm())
	if err != nil {
		log.Fatalf("could not determine which signature algorithm to use: %v", err)
	}
	signedJwt, err := jwt.Sign(*token, signatureAlg, signingKey)
	if err != nil {
		log.Fatalf("cannot sign token with our key: %v", err)
	}
	return string(signedJwt)
}

func getSignatureAlgorithm(name string) (alg jwa.SignatureAlgorithm, err error) {
	err = alg.Accept(name)
	return
}

func validateProviderJWT(token string) (err error) {
	// validates a token claims and signature
	_, err = jwt.ParseString(token, jwt.WithValidate(true), jwt.WithKeySet(providerPubKeySet))
	return
}
