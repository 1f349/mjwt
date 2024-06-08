package mjwt

import (
	"crypto/rand"
	"crypto/rsa"
	"github.com/1f349/rsa-helper/rsaprivate"
	"github.com/1f349/rsa-helper/rsapublic"
	"github.com/stretchr/testify/assert"
	"os"
	"path"
	"testing"
)

func TestNewMJwtKeyStoreFromDirectory(t *testing.T) {
	t.Parallel()
	tempDir, err := os.MkdirTemp("", "this-is-a-test-dir")
	assert.NoError(t, err)

	const prvExt = "prv"
	const pubExt = "pub"

	key1, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)
	err = rsaprivate.Write(path.Join(tempDir, "key1.pem."+prvExt), key1)
	assert.NoError(t, err)

	key2, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)
	err = rsaprivate.Write(path.Join(tempDir, "key2.pem."+prvExt), key2)
	assert.NoError(t, err)
	err = rsapublic.Write(path.Join(tempDir, "key2.pem."+pubExt), &key2.PublicKey)
	assert.NoError(t, err)

	key3, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)
	err = rsapublic.Write(path.Join(tempDir, "key3.pem."+pubExt), &key3.PublicKey)
	assert.NoError(t, err)

	kStore, err := NewMJwtKeyStoreFromDirectory(tempDir, "prv", "pub")
	assert.NoError(t, err)

	assert.Len(t, kStore.ListKeys(), 3)
	kIDsToFind := []string{"key1", "key2", "key3"}
	for _, k := range kIDsToFind {
		assert.Contains(t, kStore.ListKeys(), k)
	}
}
