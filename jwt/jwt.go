package jwt

import (
	"encoding/json"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"net/http"
	"strings"
	"time"
)

// Credentials is a struct containing the username and password
// of the user to be authenticated. This data is expected to be
// in the body of the POST request to the /authenticate endpoint
// in JSON form.
type Credentials struct {
	Username string
	Password string
}

// AuthorizationFunction is a function that takes Credentials and
// returns true if the credentials are valid, false otherwise.
type AuthorizationFunction func(Credentials) bool

// JWTAuthenticator is a middleware that provides an /authenticate
// endpoint that can authenticate a user and generate a JWT token.
type JWTAuthenticator struct {
	handler       http.Handler
	key           []byte
	tokenLifetime int64
	authenticate  AuthorizationFunction
}

// NewJWTAuthenticator constructs a new authenticator middleware using
// the given secret key, token lifetime in minutes, and AuthorizationFunction.
func NewJWTAuthenticator(key []byte, tokenLifetime int64, authFunc AuthorizationFunction, handler http.Handler) *JWTAuthenticator {
	return &JWTAuthenticator{handler: handler, key: key, authenticate: authFunc, tokenLifetime: tokenLifetime}
}

func (j *JWTAuthenticator) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/authenticate") {
		j.authenticateUser(w, r)
	} else if j.verifyUser(r) {
		j.handler.ServeHTTP(w, r)
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "Invalid credentials")
	}
}

func (j *JWTAuthenticator) verifyUser(r *http.Request) bool {
	tokenString := r.Header.Get("Authorization")

	if !strings.HasPrefix(tokenString, "Bearer") {
		return false
	}

	tokenString = strings.TrimPrefix(tokenString, "Bearer ")

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return j.key, nil
	})

	if err != nil {
		return false
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims.VerifyExpiresAt(int64(time.Now().Unix()), true)
	}

	return false
}

func (j *JWTAuthenticator) authenticateUser(w http.ResponseWriter, r *http.Request) {
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
