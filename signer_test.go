package mjwt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func TestNewMJwtSigner(t *testing.T) {
	t.Parallel()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)
	NewMJwtSigner("Test", key)
}

func TestNewMJwtSignerFromFile(t *testing.T) {
	t.Parallel()
	tempKey, err := os.CreateTemp("", "key-test-*.pem")
	assert.NoError(t, err)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)
	b := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	_, err = tempKey.Write(b)
	assert.NoError(t, err)
	assert.NoError(t, tempKey.Close())
	signer, err := NewMJwtSignerFromFile("Test", tempKey.Name())
	assert.NoError(t, err)
	assert.NoError(t, os.Remove(tempKey.Name()))
	_, err = NewMJwtSignerFromFile("Test", tempKey.Name())
	assert.Error(t, err)
	assert.True(t, os.IsNotExist(err))
	assert.True(t, signer.(*defaultMJwtSigner).key.Equal(key))
}

func TestNewMJwtSignerFromFileOrCreate(t *testing.T) {
	t.Parallel()
	tempKey, err := os.CreateTemp("", "key-test-*.pem")
	assert.NoError(t, err)
	assert.NoError(t, tempKey.Close())
	assert.NoError(t, os.Remove(tempKey.Name()))
	signer, err := NewMJwtSignerFromFileOrCreate("Test", tempKey.Name(), rand.Reader, 2048)
	assert.NoError(t, err)
	signer2, err := NewMJwtSignerFromFileOrCreate("Test", tempKey.Name(), rand.Reader, 2048)
	assert.NoError(t, err)
	assert.True(t, signer.PrivateKey().Equal(signer2.PrivateKey()))
}

func TestReadOrCreatePrivateKey(t *testing.T) {
	t.Parallel()
	tempKey, err := os.CreateTemp("", "key-test-*.pem")
	assert.NoError(t, err)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)
	b := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	_, err = tempKey.Write(b)
	assert.NoError(t, err)
	assert.NoError(t, tempKey.Close())
	key2, err := readOrCreatePrivateKey(tempKey.Name(), rand.Reader, 2048)
	assert.NoError(t, err)
	assert.True(t, key.Equal(key2))
	assert.NoError(t, os.Remove(tempKey.Name()))
	key3, err := readOrCreatePrivateKey(tempKey.Name(), rand.Reader, 2048)
	assert.NoError(t, err)
	assert.NoError(t, key3.Validate())
}
