package jwt

import (
	"errors"
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
)

// GenerateToken generates a JWT for the given username
func GenerateToken(username string, client string, key []byte, tokenType string, ttl int64) (string, error) {
	claims := jwt.MapClaims{}
	claims["username"] = username
	claims["client"] = client
	claims["token_type"] = tokenType

	if ttl != 0 {
		claims["exp"] = ttl
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString(key)

	return tokenString, err
}

// GetUserFromToken extracts the "username" field from the given JWT and returns it if the
// JWT is valid
func GetUserFromToken(token string, claimedClient string, key []byte, verifyExpires bool, expectedTokenType string) (string, error) {
	parser := jwt.Parser{SkipClaimsValidation: !verifyExpires}

	parsedToken, err := parser.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return key, nil
	})

	if err != nil {
		return "", err
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)

	if !ok || !parsedToken.Valid {
		return "", errors.New("Unable to parse JWT")
	}

	if verifyExpires && !claims.VerifyExpiresAt(int64(time.Now().Unix()), true) {
		return "", errors.New("JWT is expired")
	}

	username, ok := claims["username"].(string)

	if !ok {
		return "", errors.New("Username not present in JWT")
	}

	actualClient, ok := claims["client"].(string)

	if !ok {
		return "", errors.New("Client not present in JWT")
	}

	tokenType, ok := claims["token_type"].(string)

	if !ok {
		return "", errors.New("Token type not present in JWT")
	}

	if tokenType != expectedTokenType {
		return "", fmt.Errorf("This JWT is not an %v", expectedTokenType)
	}

	if actualClient != claimedClient {
		return "", errors.New("Client in JWT does not match claimed client")
	}

	return username, nil
}
