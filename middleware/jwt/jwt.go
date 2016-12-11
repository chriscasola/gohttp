package jwt

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"net/http"
	"strings"
	"time"
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

// Authenticator is a middleware that provides an /authenticate
// endpoint that can authenticate a user and generate a JWT token.
type Authenticator struct {
	handler       http.Handler
	key           []byte
	tokenLifetime int64
	authenticate  AuthorizationFunction
	whitelist     map[string]struct{}
}

// NewAuthenticator constructs a new authenticator middleware using
// the given secret key, token lifetime in minutes, and AuthorizationFunction.
func NewAuthenticator(key []byte, tokenLifetime int64, whitelist map[string]struct{}, authFunc AuthorizationFunction, handler http.Handler) *Authenticator {
	return &Authenticator{handler: handler, key: key, authenticate: authFunc, tokenLifetime: tokenLifetime, whitelist: whitelist}
}

func (j *Authenticator) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/authenticate") {
		j.authenticateUser(w, r)
	} else if _, ok := j.whitelist[r.URL.Path]; ok {
		j.handler.ServeHTTP(w, r)
	} else if ctx, ok := j.verifyUser(r); ok {
		j.handler.ServeHTTP(w, r.WithContext(ctx))
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "Invalid credentials")
	}
}

func (j *Authenticator) verifyUser(r *http.Request) (context.Context, bool) {
	tokenString := r.Header.Get("Authorization")

	if !strings.HasPrefix(tokenString, "Bearer") {
		return nil, false
	}

	tokenString = strings.TrimPrefix(tokenString, "Bearer ")

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return j.key, nil
	})

	if err != nil {
		return nil, false
	}

	claims, ok := token.Claims.(jwt.MapClaims)

	if !ok || !token.Valid {
		return nil, false
	}

	if !claims.VerifyExpiresAt(int64(time.Now().Unix()), true) {
		return nil, false
	}

	username, ok := claims["username"].(string)

	if !ok {
		return nil, false
	}

	return context.WithValue(r.Context(), usernameContextKey, username), true
}

func (j *Authenticator) authenticateUser(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	var credentials Credentials
	err := decoder.Decode(&credentials)

	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "Malformed credentials")
		return
	}

	if !j.authenticate(credentials) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "Invalid credentials")
		return
	}

	claims := jwt.MapClaims{}
	claims["username"] = credentials.Username
	claims["exp"] = int64(time.Now().Unix() + (60 * j.tokenLifetime))

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString(j.key)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "Error signing JWT: %v", err)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(tokenString))
}
