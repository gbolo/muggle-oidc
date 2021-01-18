package oidc

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/gbolo/muggle-oidc/util"

	"github.com/spf13/viper"
)

// this is the initial request we direct the user's browser to.
// It is sent to the oidc auth endpoint and starts the whole flow.
// Defined here: https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
func GenerateAuthURL(state, redirectURL string) (authUrl string) {
	base, _ := url.Parse(discoveryCache.AuthEndpoint)
	nonce := util.GenerateRandomString(8)
	// construct query params
	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("scope", viper.GetString("oidc.scope"))
	params.Set("client_id", viper.GetString("oidc.client_id"))
	params.Set("state", state)
	params.Set("nonce", nonce)
	params.Set("redirect_uri", redirectURL)
	// pkce: https://www.oauth.com/oauth2-servers/pkce/authorization-request/
	params.Set("code_challenge", codeVerifier.CodeChallengeS256())
	params.Set("code_challenge_method", "S256")
	// request param: https://openid.net/specs/openid-connect-core-1_0.html#JWTRequests
	// details of the object: https://openid.net/specs/openid-connect-core-1_0.html#RequestObject
	// It represents the request as a JWT whose Claims are the request parameters above
	params.Set("request", createRequestJWT(state, nonce, redirectURL))
	base.RawQuery = params.Encode()

	log.Debugf("auth URL was constructed with state: %s", state)
	//log.Debugf("redirect: %s", base.String())
	return base.String()
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	IdToken     string `json:"id_token"`
}

func AccessTokenRequest(code, redirectURL string) (accessToken string, err error) {
	base, _ := url.Parse(discoveryCache.TokenEndpoint)
	// construct query params
	params := url.Values{}
	params.Set("grant_type", "authorization_code")
	params.Set("redirect_uri", redirectURL)
	params.Set("code", code)
	params.Set("client_id", viper.GetString("oidc.client_id"))

	// TODO: figure out if we can check that the provider supports this
	// https://www.oauth.com/oauth2-servers/pkce/authorization-request/
	params.Set("code_verifier", codeVerifier.String())

	// TODO: we need to decide when to use client secret or jwt
	if viper.GetString("oidc.client_secret") != "" {
		params.Set("client_secret", viper.GetString("oidc.client_secret"))
	} else {
		// when using private_key_jwt
		// https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
		params.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
		params.Set("client_assertion", createAssertionJWT())
	}

	headers := map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
	}
	resp := doHttpCall("POST", base.String(), headers, []byte(params.Encode()))

	// handle any errors
	if resp.err != nil {
		err = resp.err
		return
	}
	if resp.StatusCode != 200 {
		err = fmt.Errorf("token url returned a non-200 status: %v with body: %s", resp.StatusCode, resp.BodyBytes)
		return
	}

	// parse the token response
	var tr tokenResponse
	err = json.Unmarshal(resp.BodyBytes, &tr)
	if err != nil {
		return
	}

	// validate the ID token if it exists (log warning if it doesnt for now)
	if tr.IdToken != "" {
		err = validateProviderJWT(tr.IdToken)
		if err == nil {
			log.Info("id_token was successfully validated")
		} else {
			log.Errorf("id_token could not be validated: %v", err)
			log.Debugf("bad id_token: %s", tr.IdToken)
		}
	} else {
		log.Warning("token response did not contain an id_token")
	}

	accessToken = tr.AccessToken
	return
}

func UserInfoRequest(accessToken string) (responseBody []byte, err error) {
	headers := map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", accessToken),
	}
	resp := doHttpCall("GET", discoveryCache.UserinfoEndpoint, headers, nil)

	// handle any errors
	if resp.err != nil {
		err = resp.err
		return
	}
	if resp.StatusCode != 200 {
		err = fmt.Errorf("userinfo url returned a non-200 status: %v with body: %s", resp.StatusCode, resp.BodyBytes)
		return
	}
	responseBody = resp.BodyBytes
	return
}
