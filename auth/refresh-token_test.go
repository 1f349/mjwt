package auth

import (
	"github.com/1f349/mjwt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestCreateRefreshToken(t *testing.T) {
	t.Parallel()

	kStore := mjwt.NewKeyStore()
	s, err := mjwt.NewIssuerWithKeyStore("mjwt.test", "key1", kStore)
	assert.NoError(t, err)

	refreshToken, err := CreateRefreshToken(s, "1", "test", "test2", nil)
	assert.NoError(t, err)

	_, b, err := mjwt.ExtractClaims[RefreshTokenClaims](kStore, refreshToken)
	assert.NoError(t, err)
	assert.Equal(t, "1", b.Subject)
	assert.Equal(t, "test", b.ID)
	assert.Equal(t, "test2", b.Claims.AccessTokenId)
}
