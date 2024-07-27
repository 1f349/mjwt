package auth

import (
	"github.com/1f349/mjwt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestCreateAccessToken(t *testing.T) {
	t.Parallel()

	ps := NewPermStorage()
	ps.Set("mjwt:test")
	ps.Set("mjwt:test2")

	kStore := mjwt.NewKeyStore()
	s, err := mjwt.NewIssuerWithKeyStore("mjwt.test", "key1", kStore)
	assert.NoError(t, err)

	accessToken, err := CreateAccessToken(s, "1", "test", nil, ps)
	assert.NoError(t, err)

	_, b, err := mjwt.ExtractClaims[AccessTokenClaims](kStore, accessToken)
	assert.NoError(t, err)
	assert.Equal(t, "1", b.Subject)
	assert.Equal(t, "test", b.ID)
	assert.True(t, b.Claims.Perms.Has("mjwt:test"))
	assert.True(t, b.Claims.Perms.Has("mjwt:test2"))
	assert.False(t, b.Claims.Perms.Has("mjwt:test3"))
}
