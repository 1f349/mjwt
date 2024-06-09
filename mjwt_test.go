package mjwt

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

var mt_ExtraKID = "tester"

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

func setupTestKeyStoreMJWT(t *testing.T) (ks KeyStore, a, b, c *rsa.PrivateKey) {
	ks = NewMJwtKeyStore()
	var err error

	a, err = rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)
	ks.SetKey("key1", a)

	b, err = rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)
	ks.SetKey("key2", b)

	c, err = rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)
	ks.SetKey("key3", c)

	return
}

func TestExtractClaims(t *testing.T) {
	t.Parallel()
	kStore, key, _, _ := setupTestKeyStoreMJWT(t)

	t.Run("TestNoKID", func(t *testing.T) {
		t.Parallel()
		s := NewMJwtSigner("mjwt.test", key)
		token, err := s.GenerateJwt("1", "test", nil, 10*time.Minute, testClaims{TestValue: "hello"})
		assert.NoError(t, err)

		m := NewMJwtVerifier(&key.PublicKey)
		_, _, err = ExtractClaims[testClaims](m, token)
		assert.NoError(t, err)
	})

	t.Run("TestKID", func(t *testing.T) {
		t.Parallel()
		s := NewMJwtSignerWithKeyStore("mjwt.test", key, kStore)
		token1, err := s.GenerateJwt("1", "test", nil, 10*time.Minute, testClaims{TestValue: "hello"})
		assert.NoError(t, err)
		token2, err := s.GenerateJwtWithKID("1", "test", nil, 10*time.Minute, testClaims{TestValue: "hello"}, "key2")
		assert.NoError(t, err)

		m := NewMJwtVerifierWithKeyStore(&key.PublicKey, kStore)
		_, _, err = ExtractClaims[testClaims](m, token1)
		assert.NoError(t, err)
		_, _, err = ExtractClaims[testClaims](m, token2)
		assert.NoError(t, err)
	})
}

func TestExtractClaimsFail(t *testing.T) {
	t.Parallel()
	kStore, key, key2, _ := setupTestKeyStoreMJWT(t)

	t.Run("TestInvalidClaims", func(t *testing.T) {
		t.Parallel()
		s := NewMJwtSigner("mjwt.test", key)
		token, err := s.GenerateJwt("1", "test", nil, 10*time.Minute, testClaims{TestValue: "test"})
		assert.NoError(t, err)

		m := NewMJwtVerifier(&key.PublicKey)
		_, _, err = ExtractClaims[testClaims2](m, token)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrClaimTypeMismatch)
	})

	t.Run("TestDefaultKeyNoKID", func(t *testing.T) {
		t.Parallel()
		s := NewMJwtSignerWithKeyStore("mjwt.test", key, kStore)
		token, err := s.GenerateJwtWithKID("1", "test", nil, 10*time.Minute, testClaims{TestValue: "test"}, "key1")
		assert.NoError(t, err)

		m := NewMJwtVerifier(&key.PublicKey)
		_, _, err = ExtractClaims[testClaims](m, token)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrNoPublicKeyFound)
	})

	t.Run("TestNoDefaultKey", func(t *testing.T) {
		t.Parallel()
		s := NewMJwtSignerWithKeyStore("mjwt.test", key, kStore)
		token, err := s.GenerateJwt("1", "test", nil, 10*time.Minute, testClaims{TestValue: "test"})
		assert.NoError(t, err)

		m := NewMJwtVerifierWithKeyStore(nil, kStore)
		_, _, err = ExtractClaims[testClaims](m, token)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrNoPublicKeyFound)
	})

	t.Run("TestKIDNonExist", func(t *testing.T) {
		t.Parallel()
		kStore.SetKey(mt_ExtraKID, key2)
		assert.Contains(t, kStore.ListKeys(), mt_ExtraKID)

		s := NewMJwtSignerWithKeyStore("mjwt.test", key, kStore)
		token, err := s.GenerateJwtWithKID("1", "test", nil, 10*time.Minute, testClaims{TestValue: "test"}, mt_ExtraKID)
		assert.NoError(t, err)

		kStore.RemoveKey(mt_ExtraKID)
		assert.NotContains(t, kStore.ListKeys(), mt_ExtraKID)

		m := NewMJwtVerifierWithKeyStore(&key.PublicKey, kStore)
		_, _, err = ExtractClaims[testClaims](m, token)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrNoPublicKeyFound)
	})
}
