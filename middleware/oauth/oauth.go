package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/chriscasola/gohttp"
	"github.com/chriscasola/gohttp/middleware/jwt"
)

type contextKey int

// Credentials is a struct containing the username and password
// of the user to be authenticated. This data is expected to be
// in the body of the POST request to the /authenticate endpoint
// in JSON form.
type Credentials struct {
	Username string
	Password string
}

type oauthResponseBody struct {
	TokenType    string `json:"token_type"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    int64  `json:"expires_in"`
}

const usernameContextKey contextKey = 0

// GetUsernameFromContext returns the username associated with
// the request
func GetUsernameFromContext(ctx context.Context) (string, bool) {
	username, ok := ctx.Value(usernameContextKey).(string)
	return username, ok
}

// AuthorizationFunction is a function that takes Credentials and
// returns true if the credentials are valid, false otherwise.
type AuthorizationFunction func(Credentials) bool

// ClientVerificationFunction is a function that takes in a client ID
// and a claimed shared secret and returns true if the secret is valid
type ClientVerificationFunction func(clientID string, claimedSecret string) bool

// Middleware is a middleware that provides an /authenticate
// endpoint that can authenticate a user and generate a JWT token.
// It also provides /oauth/token and /oauth/authorize endpoints that
// implement the oauth2 spec as described in
// https://developers.google.com/actions/identity/oauth2-code-flow
type Middleware struct {
	handler       http.Handler
	key           []byte
	tokenLifetime int64
	authenticate  AuthorizationFunction
	whitelist     map[string]struct{}
	verifyClient  ClientVerificationFunction
}

// New constructs a new authenticator middleware using
// the given secret key, token lifetime in minutes, and AuthorizationFunction.
func New(key []byte, tokenLifetime int64, whitelist map[string]struct{}, authFunc AuthorizationFunction, verifyClient ClientVerificationFunction, handler http.Handler) *Middleware {
	return &Middleware{handler: handler, key: key, authenticate: authFunc, tokenLifetime: tokenLifetime, whitelist: whitelist, verifyClient: verifyClient}
}

func (m *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/authenticate") {
		m.authenticateUser(w, r)
	} else if strings.HasPrefix(r.URL.Path, "/oauth/token") {
		m.oauthExchange(w, r)
	} else if strings.HasPrefix(r.URL.Path, "/oauth/authorize") {
		m.oauthAuthorize(w, r)
	} else if _, ok := m.whitelist[r.URL.Path]; ok {
		m.handler.ServeHTTP(w, r)
	} else if ctx, ok := m.verifyUser(r); ok {
		m.handler.ServeHTTP(w, r.WithContext(ctx))
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "Invalid credentials")
	}
}

func (m *Middleware) verifyUser(r *http.Request) (context.Context, bool) {
	tokenString := r.Header.Get("Authorization")

	if !strings.HasPrefix(tokenString, "Bearer") {
		return nil, false
	}

	tokenString = strings.TrimPrefix(tokenString, "Bearer ")

	username, err := jwt.GetUserFromToken(tokenString, "", m.key, true, "access")

	if err != nil {
		return nil, false
	}

	return context.WithValue(r.Context(), usernameContextKey, username), true
}

func (m *Middleware) authenticateUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	decoder := json.NewDecoder(r.Body)
	var credentials Credentials
	err := decoder.Decode(&credentials)

	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "Malformed credentials")
		return
	}

	if !m.authenticate(credentials) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "Invalid credentials")
		return
	}

	tokenString, err := jwt.GenerateToken(credentials.Username, "", m.key, "access", int64(time.Now().Unix()+(60*m.tokenLifetime)))

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "Error signing JWT: %v", err)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(tokenString))
}

func (m *Middleware) oauthAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	decoder := json.NewDecoder(r.Body)
	var credentials Credentials
	err := decoder.Decode(&credentials)

	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "Malformed credentials")
		return
	}

	if !m.authenticate(credentials) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "Invalid credentials")
		return
	}

	client := r.URL.Query().Get("client_id")

	tokenString, err := generateAuthorizationToken(credentials.Username, client, m.key)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "Error signing JWT: %v", err)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(tokenString))
}

func (m *Middleware) oauthExchange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		sendOauthError(w)
		return
	}

	queryArgs := r.PostForm
	clientID, clientSecret, grantType := queryArgs.Get("client_id"), queryArgs.Get("client_secret"), queryArgs.Get("grant_type")

	if !m.verifyClient(clientID, clientSecret) {
		sendOauthError(w)
		return
	}

	oauthBody := oauthResponseBody{
		TokenType: "bearer",
	}

	var err error
	refreshToken := ""

	if grantType == "authorization_code" {
		authToken := queryArgs.Get("code")

		refreshToken, err = generateRefreshTokenFromAuthorizationToken(authToken, clientID, m.key)
		if err != nil {
			sendOauthError(w)
			return
		}

		oauthBody.RefreshToken = refreshToken
	}

	if grantType == "refresh_token" {
		refreshToken = queryArgs.Get("refresh_token")
	}

	accessToken, expiresIn, err := generateAccessTokenFromRefreshToken(refreshToken, clientID, m.key)
	if err != nil {
		sendOauthError(w)
		return
	}

	oauthBody.AccessToken = accessToken
	oauthBody.ExpiresIn = expiresIn

	gohttp.SendJSON(w, http.StatusOK, oauthBody)
}

func sendOauthError(w http.ResponseWriter) {
	w.WriteHeader(http.StatusBadRequest)
	fmt.Fprint(w, "{\"error\":\"invalid_grant\"}")
}

func generateAccessTokenFromRefreshToken(refreshToken string, claimedClient string, key []byte) (string, int64, error) {
	username, err := getUserFromRefreshToken(refreshToken, claimedClient, key)
	if err != nil {
		return "", 0, err
	}

	return generateAccessToken(username, key)
}

func generateRefreshTokenFromAuthorizationToken(authorizationToken, claimedClient string, key []byte) (string, error) {
	username, err := getUserFromAuthorizationToken(authorizationToken, claimedClient, key)
	if err != nil {
		return "", err
	}

	return generateRefreshToken(username, claimedClient, key)
}

func generateAccessToken(username string, key []byte) (string, int64, error) {
	lifetime := int64(60 * 60) // 1 hour
	expTime := int64(time.Now().Unix()) + lifetime
	token, err := jwt.GenerateToken(username, "", key, "access", expTime)
	return token, expTime, err
}

func generateRefreshToken(username string, client string, key []byte) (string, error) {
	return jwt.GenerateToken(username, client, key, "refresh", 0)
}

func getUserFromRefreshToken(token string, claimedClient string, key []byte) (string, error) {
	return jwt.GetUserFromToken(token, claimedClient, key, false, "refresh")
}

func generateAuthorizationToken(username string, client string, key []byte) (string, error) {
	expTime := int64(time.Now().Unix()) + (60 * 10) // 10 minutes
	return jwt.GenerateToken(username, client, key, "authorization_code", expTime)
}

func getUserFromAuthorizationToken(token string, claimedClient string, key []byte) (string, error) {
	return jwt.GetUserFromToken(token, claimedClient, key, true, "authorization_code")
}
