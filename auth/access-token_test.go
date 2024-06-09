package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"github.com/1f349/mjwt"
	"github.com/1f349/mjwt/claims"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestCreateAccessToken(t *testing.T) {
	t.Parallel()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	ps := claims.NewPermStorage()
	ps.Set("mjwt:test")
	ps.Set("mjwt:test2")

	s := mjwt.NewMJwtSigner("mjwt.test", key)

	accessToken, err := CreateAccessToken(s, "1", "test", nil, ps)
	assert.NoError(t, err)

	_, b, err := mjwt.ExtractClaims[AccessTokenClaims](s, accessToken)
	assert.NoError(t, err)
	assert.Equal(t, "1", b.Subject)
	assert.Equal(t, "test", b.ID)
	assert.True(t, b.Claims.Perms.Has("mjwt:test"))
	assert.True(t, b.Claims.Perms.Has("mjwt:test2"))
	assert.False(t, b.Claims.Perms.Has("mjwt:test3"))
}

func TestCreateAccessTokenInvalid(t *testing.T) {
	t.Parallel()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	kStore := mjwt.NewMJwtKeyStore()
	kStore.SetKey("test", key)

	ps := claims.NewPermStorage()
	ps.Set("mjwt:test")
	ps.Set("mjwt:test2")

	s := mjwt.NewMJwtSignerWithKeyStore("mjwt.test", nil, kStore)

	accessToken, err := CreateAccessTokenWithKID(s, "1", "test", nil, ps, "test")
	assert.NoError(t, err)

	_, b, err := mjwt.ExtractClaims[AccessTokenClaims](s, accessToken)
	assert.NoError(t, err)
	assert.Equal(t, "1", b.Subject)
	assert.Equal(t, "test", b.ID)
	assert.True(t, b.Claims.Perms.Has("mjwt:test"))
	assert.True(t, b.Claims.Perms.Has("mjwt:test2"))
	assert.False(t, b.Claims.Perms.Has("mjwt:test3"))
}
