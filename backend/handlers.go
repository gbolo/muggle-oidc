package backend

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gbolo/muggle-oidc/oidc"
	"github.com/gbolo/muggle-oidc/util"
	"github.com/spf13/viper"
)

// for now, we dont worry about sessions. use the same state always
var defaultState = "D2FjBT2M2tqs5CFF"

const sessionCookieName = "muggleOIDC_SESSION_ID"

func handlerLanding(w http.ResponseWriter, req *http.Request) {
	htmlText := fmt.Sprintf(
		"<h1>Test OIDC DAC Integration</h1><br/>To begin an OIDC DAC flow, follow this link: <a href=\"%s\">%s</a>",
		authPath,
		authPath,
	)
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(htmlText))
}

// @Summary Returns version information
// @Description Returns version information
// @Tags Misc
// @Produce json
// @Success 200 {object} versionInfo
// @Router /v1/version [get]
func handlerVersion(w http.ResponseWriter, req *http.Request) {
	writeJSONResponse(w, http.StatusOK, getVersionResponse())
}

// @Summary Returns our JWKS so that our signatures can be verified
// @Description Returns our JWKS so that our signatures can be verified
// @Tags Misc
// @Produce json
// @Success 200 {object} jwk.Set
// @Router /v1/jwks [get]
func handlerJwks(w http.ResponseWriter, req *http.Request) {
	w.Write(oidc.GetPublicJWKS())
}

// @Summary Starts the flow
// @Description Starts the flow
// @Tags Misc
// @Produce json
// @Success 302
// @Router /v1/auth [get]
func handlerAuthRedirect(w http.ResponseWriter, req *http.Request) {
	// check if we have a session ID
	sessionID := ""
	sessionCookie, _ := req.Cookie(sessionCookieName)
	if sessionCookie == nil {
		// create a new session ID and set it as a cookie
		sessionID = util.GenerateRandomString(16)
		http.SetCookie(w, &http.Cookie{
			Name:     sessionCookieName,
			Value:    sessionID,
			Path:     "/",
			Secure:   true,
			HttpOnly: false,
			Expires:  time.Now().Add(time.Hour * 1),
			SameSite: http.SameSiteNoneMode,
		})
	} else {
		sessionID = sessionCookie.Value
	}

	// create a new state value and store it for future validation
	state := util.GenerateRandomString(32)
	oidc.StateStore.AddState(sessionID, state)

	// generate then return auth URL as a redirect
	callbackURL := fmt.Sprintf("%s%s", viper.GetString("external_self_baseurl"), callbackPath)
	http.Redirect(w, req, oidc.GenerateAuthURL(state, callbackURL), http.StatusFound)
}

// @Summary Callback handler
// @Description Callback handler
// @Tags Misc
// @Produce json
// @Success 200
// @Router /v1/callback [get]
func handlerCallback(w http.ResponseWriter, req *http.Request) {
	// check that we have the expected state for this browser
	sessionCookie, _ := req.Cookie(sessionCookieName)
	if sessionCookie == nil {
		writeJSONResponse(w, http.StatusBadRequest, errorResponse{"your request did not contain an expected session cookie"})
		return
	}
	if !oidc.StateStore.ValidateState(sessionCookie.Value, req.FormValue("state")) {
		log.Errorf("could not validate the state provided: %s", req.FormValue("state"))
		writeJSONResponse(w, http.StatusBadRequest, errorResponse{"provided state did not match expected state"})
		return
	}
	log.Debugf("callback state matched expected state")

	// check that the user request includes a code
	code := req.FormValue("code")
	if code == "" {
		log.Errorf("code is missing from callback request")
		writeJSONResponse(w, http.StatusBadRequest, errorResponse{"did not provide a code"})
		return
	}

	// use the code to get an access token
	callbackURL := fmt.Sprintf("%s%s", viper.GetString("external_self_baseurl"), callbackPath)
	accessToken, err := oidc.AccessTokenRequest(code, callbackURL)
	if err != nil {
		errMsg := fmt.Sprintf("could not retrieve an access token: %v", err)
		log.Errorf(errMsg)
		writeJSONResponse(w, http.StatusInternalServerError, errorResponse{errMsg})
		return
	}
	log.Debugf("retrieved an access token: %s", accessToken)

	// use access token to fetch userinfo
	userInfoResp, err := oidc.UserInfoRequest(accessToken)
	if err != nil {
		errMsg := fmt.Sprintf("could not retrieve user info response: %v", err)
		log.Errorf(errMsg)
		writeJSONResponse(w, http.StatusInternalServerError, errorResponse{errMsg})
		return
	}
	w.Write(userInfoResp)
}

// wrapper for json responses
func writeJSONResponse(w http.ResponseWriter, status int, body interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	b, _ := json.MarshalIndent(body, "", "  ")
	w.Write(b)
}
