package mjwt

import (
	"crypto/rand"
	"crypto/rsa"
	"github.com/1f349/rsa-helper/rsaprivate"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNewIssuer(t *testing.T) {
	t.Parallel()
	t.Run("generate missing key for issuer", func(t *testing.T) {
		t.Parallel()
		kStore := NewKeyStore()
		issuer, err := NewIssuerWithKeyStore("Test", "test", kStore)
		assert.NoError(t, err)
		assert.True(t, kStore.HasPrivateKey("test"))
		assert.True(t, kStore.HasPublicKey("test"))
		assert.Equal(t, "Test", issuer.issuer)
		assert.Equal(t, "test", issuer.kid)
	})
	t.Run("use existing issuer key", func(t *testing.T) {
		t.Parallel()
		kStore := NewKeyStore()
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		assert.NoError(t, err)
		kStore.LoadPrivateKey("test", key)
		issuer, err := NewIssuerWithKeyStore("Test", "test", kStore)
		assert.NoError(t, err)
		assert.True(t, kStore.HasPrivateKey("test"))
		assert.True(t, kStore.HasPublicKey("test"))
		assert.Equal(t, "Test", issuer.issuer)
		assert.Equal(t, "test", issuer.kid)
		privateKey, err := issuer.PrivateKey()
		assert.NoError(t, err)
		assert.True(t, key.Equal(privateKey))
	})
	t.Run("generate missing key in filesystem", func(t *testing.T) {
		t.Parallel()
		dir := afero.NewMemMapFs()
		kStore := NewKeyStoreWithDir(dir)
		issuer, err := NewIssuerWithKeyStore("Test", "test", kStore)
		assert.NoError(t, err)
		assert.True(t, kStore.HasPrivateKey("test"))
		assert.True(t, kStore.HasPublicKey("test"))
		assert.Equal(t, "Test", issuer.issuer)
		assert.Equal(t, "test", issuer.kid)
		privKeyFile, err := dir.Open("test.private.pem")
		assert.NoError(t, err)
		privKey, err := rsaprivate.Decode(privKeyFile)
		assert.NoError(t, err)
		key, err := issuer.PrivateKey()
		assert.NoError(t, err)
		assert.True(t, key.Equal(privKey))
	})
}
