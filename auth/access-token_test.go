package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"github.com/MrMelon54/mjwt"
	"github.com/MrMelon54/mjwt/claims"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestCreateAccessToken(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	ps := claims.NewPermStorage()
	ps.Set("mjwt:test")
	ps.Set("mjwt:test2")

	s := mjwt.NewMJwtSigner("mjwt.test", key)

	accessToken, err := CreateAccessToken(s, "1", "test", 1, ps)
	assert.NoError(t, err)

	_, b, err := mjwt.ExtractClaims[AccessTokenClaims](s, accessToken)
	assert.NoError(t, err)
	assert.Equal(t, "1", b.Subject)
	assert.Equal(t, "test", b.ID)
	assert.Equal(t, uint64(1), b.Claims.UserId)
	assert.True(t, b.Claims.Perms.Has("mjwt:test"))
	assert.True(t, b.Claims.Perms.Has("mjwt:test2"))
	assert.False(t, b.Claims.Perms.Has("mjwt:test3"))
}
