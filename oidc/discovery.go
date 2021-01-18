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
