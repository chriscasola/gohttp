package oauth

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

func getKey() ([]byte, error) {
	randomData := make([]byte, 256)
	_, err := rand.Read(randomData)

	if err != nil {
		return nil, err
	}

	return randomData, nil
}

func TestAuthorizationTokens(t *testing.T) {
	goodKey, err := getKey()
	assert.NoError(t, err, "generate good key")

	validToken, err := generateAuthorizationToken("ccasola", "google", goodKey)
	assert.NoError(t, err, "generate authorization token")

	user, err := getUserFromAuthorizationToken(validToken, "google", goodKey)
	assert.NoError(t, err, "unexpected error getting user from valid authorization token")

	assert.Equal(t, "ccasola", user, "get user from authorization token")

	_, err = getUserFromAuthorizationToken("bad token", "google", goodKey)
	assert.Error(t, err, "return error when token is not a valid JWT")

	_, err = getUserFromAuthorizationToken(validToken, "yahoo", goodKey)
	assert.Error(t, err, "return error when claimed client does not match client in JWT")
}

func TestRefreshTokens(t *testing.T) {
	goodKey, err := getKey()
	assert.NoError(t, err, "generate good key")

	validToken, err := generateRefreshToken("ccasola", "google", goodKey)
	assert.NoError(t, err, "generate refresh token")

	user, err := getUserFromRefreshToken(validToken, "google", goodKey)
	assert.NoError(t, err, "unexpected error getting user from valid refresh token")

	assert.Equal(t, "ccasola", user, "get user from refresh token")

	_, err = getUserFromRefreshToken("bad token", "google", goodKey)
	assert.Error(t, err, "return error when token is not a valid JWT")

	_, err = getUserFromRefreshToken(validToken, "yahoo", goodKey)
	assert.Error(t, err, "return error when claimed client does not match client in JWT")
}
