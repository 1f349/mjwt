package mjwt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"github.com/1f349/rsa-helper/rsaprivate"
	"github.com/1f349/rsa-helper/rsapublic"
	"github.com/stretchr/testify/assert"
	"os"
	"path"
	"testing"
)

const st_prvExt = "prv"
const st_pubExt = "pub"

func setupTestDirSigner(t *testing.T) (string, *rsa.PrivateKey, func(t *testing.T)) {
	tempDir, err := os.MkdirTemp("", "this-is-a-test-dir")
	assert.NoError(t, err)

	var key3 *rsa.PrivateKey = nil
	key1, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)
	err = rsaprivate.Write(path.Join(tempDir, "key1.pem."+st_prvExt), key1)
	assert.NoError(t, err)

	key2, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)
	err = rsaprivate.Write(path.Join(tempDir, "key2.pem."+st_prvExt), key2)
	assert.NoError(t, err)
	err = rsapublic.Write(path.Join(tempDir, "key2.pem."+st_pubExt), &key2.PublicKey)
	assert.NoError(t, err)

	key3, err = rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)
	err = rsapublic.Write(path.Join(tempDir, "key3.pem."+st_pubExt), &key3.PublicKey)
	assert.NoError(t, err)

	return tempDir, key3, func(t *testing.T) {
		err := os.RemoveAll(tempDir)
		assert.NoError(t, err)
	}
}

func TestNewMJwtSigner(t *testing.T) {
	t.Parallel()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)
	NewMJwtSigner("Test", key)
}

func TestNewMJwtSignerWithKeyStore(t *testing.T) {
	t.Parallel()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)
	kStore := NewMJwtKeyStore()
	kStore.SetKey("test", key)
	assert.Contains(t, kStore.ListKeys(), "test")
	NewMJwtSignerWithKeyStore("Test", nil, kStore)
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

func TestNewMJwtSignerFromDirectory(t *testing.T) {
	t.Parallel()

	tempDir, prvKey3, cleaner := setupTestDirSigner(t)
	defer cleaner(t)

	signer, err := NewMJwtSignerFromDirectory("Test", tempDir, st_prvExt, st_pubExt)
	assert.NoError(t, err)

	assert.Len(t, signer.GetKeyStore().ListKeys(), 3)
	kIDsToFind := []string{"key1", "key2", "key3"}
	for _, k := range kIDsToFind {
		assert.Contains(t, signer.GetKeyStore().ListKeys(), k)
	}
	assert.True(t, prvKey3.PublicKey.Equal(signer.GetKeyStore().GetKeyPublic("key3")))
}

func TestNewMJwtSignerFromFileAndDirectory(t *testing.T) {
	t.Parallel()

	tempDir, prvKey3, cleaner := setupTestDirSigner(t)
	defer cleaner(t)

	signer, err := NewMJwtSignerFromFileAndDirectory("Test", path.Join(tempDir, "key1.pem."+st_prvExt), tempDir, st_prvExt, st_pubExt)
	assert.NoError(t, err)

	assert.Len(t, signer.GetKeyStore().ListKeys(), 3)
	kIDsToFind := []string{"key1", "key2", "key3"}
	for _, k := range kIDsToFind {
		assert.Contains(t, signer.GetKeyStore().ListKeys(), k)
	}
	assert.True(t, prvKey3.PublicKey.Equal(signer.GetKeyStore().GetKeyPublic("key3")))
	assert.True(t, signer.PrivateKey().Equal(signer.GetKeyStore().GetKey("key1")))
}
