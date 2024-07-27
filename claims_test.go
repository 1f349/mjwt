package mjwt

import (
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
	kStore := NewKeyStore()

	t.Run("TestNoKID", func(t *testing.T) {
		t.Parallel()
		s, err := NewIssuerWithKeyStore("mjwt.test", "key1", kStore)
		assert.NoError(t, err)
		token, err := s.GenerateJwt("1", "test", nil, 10*time.Minute, testClaims{TestValue: "hello"})
		assert.NoError(t, err)

		a, _, err := ExtractClaims[testClaims](kStore, token)
		assert.NoError(t, err)
		kid, _ := a.Header["kid"].(string)
		assert.Equal(t, "key1", kid)
	})

	t.Run("TestKID", func(t *testing.T) {
		t.Parallel()
		s, err := NewIssuerWithKeyStore("mjwt.test", "key2", kStore)
		assert.NoError(t, err)
		s2, err := NewIssuerWithKeyStore("mjwt.test", "key3", kStore)
		assert.NoError(t, err)

		token1, err := s.GenerateJwt("1", "test", nil, 10*time.Minute, testClaims{TestValue: "hello"})
		assert.NoError(t, err)
		token2, err := s2.GenerateJwt("2", "test", nil, 10*time.Minute, testClaims{TestValue: "hello"})
		assert.NoError(t, err)

		k1, _, err := ExtractClaims[testClaims](kStore, token1)
		assert.NoError(t, err)
		k2, _, err := ExtractClaims[testClaims](kStore, token2)
		assert.NoError(t, err)
		assert.NotEqual(t, k1.Header["kid"], k2.Header["kid"])
	})
}

func TestExtractClaimsFail(t *testing.T) {
	t.Parallel()
	kStore := NewKeyStore()

	t.Run("TestInvalidClaims", func(t *testing.T) {
		t.Parallel()
		s, err := NewIssuerWithKeyStore("mjwt.test", "key1", kStore)
		assert.NoError(t, err)
		token, err := s.GenerateJwt("1", "test", nil, 10*time.Minute, testClaims{TestValue: "test"})
		assert.NoError(t, err)

		_, _, err = ExtractClaims[testClaims2](kStore, token)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrClaimTypeMismatch)
	})

	t.Run("TestKIDNonExist", func(t *testing.T) {
		t.Parallel()

		s, err := NewIssuerWithKeyStore("mjwt.test", "key2", kStore)
		assert.NoError(t, err)
		token, err := s.GenerateJwt("1", "test", nil, 10*time.Minute, testClaims{TestValue: "test"})
		assert.NoError(t, err)

		kStore.RemoveKey("key2")
		assert.NotContains(t, kStore.ListKeys(), "key2")

		_, _, err = ExtractClaims[testClaims](kStore, token)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrMissingPublicKey)
	})
}
