package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"github.com/MrMelon54/mjwt"
	"github.com/MrMelon54/mjwt/claims"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestCreateTokenPair(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	ps := claims.NewPermStorage()
	ps.Set("mjwt:test")
	ps.Set("mjwt:test2")

	s := mjwt.NewMJwtSigner("mjwt.test", key)

	accessToken, refreshToken, err := CreateTokenPair(s, "1", "test", "test2", nil, nil, ps)
	assert.NoError(t, err)

	_, b, err := mjwt.ExtractClaims[AccessTokenClaims](s, accessToken)
	assert.NoError(t, err)
	assert.Equal(t, "1", b.Subject)
	assert.Equal(t, "test", b.ID)
	assert.True(t, b.Claims.Perms.Has("mjwt:test"))
	assert.True(t, b.Claims.Perms.Has("mjwt:test2"))
	assert.False(t, b.Claims.Perms.Has("mjwt:test3"))

	_, b2, err := mjwt.ExtractClaims[RefreshTokenClaims](s, refreshToken)
	assert.NoError(t, err)
	assert.Equal(t, "1", b2.Subject)
	assert.Equal(t, "test2", b2.ID)
}
