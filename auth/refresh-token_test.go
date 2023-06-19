package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"github.com/MrMelon54/mjwt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestCreateRefreshToken(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	s := mjwt.NewMJwtSigner("mjwt.test", key)

	refreshToken, err := CreateRefreshToken(s, "1", "test", "test2", nil)
	assert.NoError(t, err)

	_, b, err := mjwt.ExtractClaims[RefreshTokenClaims](s, refreshToken)
	assert.NoError(t, err)
	assert.Equal(t, "1", b.Subject)
	assert.Equal(t, "test", b.ID)
	assert.Equal(t, "test2", b.Claims.AccessTokenId)
}
