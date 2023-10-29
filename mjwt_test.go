package mjwt

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

type testClaims struct{ TestValue string }

func (t testClaims) Valid() error {
	if t.TestValue != "hello" && t.TestValue != "world" {
		return fmt.Errorf("TestValue should be hello")
	}
	return nil
}

func (t testClaims) Type() string { return "testClaims" }

type testClaims2 struct{ TestValue2 string }

func (t testClaims2) Valid() error {
	if t.TestValue2 != "world" {
		return fmt.Errorf("TestValue2 should be world")
	}
	return nil
}

func (t testClaims2) Type() string { return "testClaims2" }

func TestExtractClaims(t *testing.T) {
	t.Parallel()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	s := NewMJwtSigner("mjwt.test", key)
	token, err := s.GenerateJwt("1", "test", nil, 10*time.Minute, testClaims{TestValue: "hello"})
	assert.NoError(t, err)

	m := NewMJwtVerifier(&key.PublicKey)
	_, _, err = ExtractClaims[testClaims](m, token)
	assert.NoError(t, err)
}

func TestExtractClaimsFail(t *testing.T) {
	t.Parallel()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	s := NewMJwtSigner("mjwt.test", key)
	token, err := s.GenerateJwt("1", "test", nil, 10*time.Minute, testClaims{TestValue: "test"})
	assert.NoError(t, err)

	m := NewMJwtVerifier(&key.PublicKey)
	_, _, err = ExtractClaims[testClaims2](m, token)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrClaimTypeMismatch)
}
