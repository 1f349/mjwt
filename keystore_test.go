package mjwt

import (
	"crypto/rand"
	"crypto/rsa"
	"github.com/1f349/rsa-helper/rsaprivate"
	"github.com/1f349/rsa-helper/rsapublic"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"sort"
	"testing"
)

const kst_prvExt = "prv"
const kst_pubExt = "pub"

func setupTestDirKeyStore(t *testing.T, genKeys bool) afero.Fs {
	tempDir := afero.NewMemMapFs()

	if genKeys {
		key1, err := rsa.GenerateKey(rand.Reader, 2048)
		assert.NoError(t, err)
		err = afero.WriteFile(tempDir, "key1.private.pem", rsaprivate.Encode(key1), 0600)
		assert.NoError(t, err)

		key2, err := rsa.GenerateKey(rand.Reader, 2048)
		assert.NoError(t, err)
		err = afero.WriteFile(tempDir, "key2.private.pem", rsaprivate.Encode(key2), 0600)
		assert.NoError(t, err)
		err = afero.WriteFile(tempDir, "key2.public.pem", rsapublic.Encode(&key2.PublicKey), 0600)
		assert.NoError(t, err)

		key3, err := rsa.GenerateKey(rand.Reader, 2048)
		assert.NoError(t, err)
		err = afero.WriteFile(tempDir, "key3.public.pem", rsapublic.Encode(&key3.PublicKey), 0600)
		assert.NoError(t, err)
	}

	return tempDir
}

func commonSubTestsKeyStore(t *testing.T, kStore *KeyStore) {
	key4, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	key5, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	const extraKID1 = "key4"
	const extraKID2 = "key5"

	t.Run("TestSetKey", func(t *testing.T) {
		kStore.LoadPrivateKey(extraKID1, key4)
		assert.Contains(t, kStore.ListKeys(), extraKID1)
	})

	t.Run("TestSetKeyPublic", func(t *testing.T) {
		kStore.LoadPublicKey(extraKID2, &key5.PublicKey)
		assert.Contains(t, kStore.ListKeys(), extraKID2)
	})

	t.Run("TestGetPrivateKey", func(t *testing.T) {
		oKey, err := kStore.GetPrivateKey(extraKID1)
		assert.NoError(t, err)
		assert.Same(t, key4, oKey)
		pKey, err := kStore.GetPrivateKey(extraKID2)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrMissingPrivateKey)
		assert.Nil(t, pKey)
		aKey, err := kStore.GetPrivateKey("key1")
		assert.NoError(t, err)
		assert.NotNil(t, aKey)
		bKey, err := kStore.GetPrivateKey("key2")
		assert.NoError(t, err)
		assert.NotNil(t, bKey)
		cKey, err := kStore.GetPrivateKey("key3")
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrMissingPrivateKey)
		assert.Nil(t, cKey)
		wKey, err := kStore.GetPrivateKey("key1337")
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrMissingPrivateKey)
		assert.Nil(t, wKey)
	})

	t.Run("TestGetPublicKey", func(t *testing.T) {
		oKey, err := kStore.GetPublicKey(extraKID1)
		assert.NoError(t, err)
		assert.Same(t, &key4.PublicKey, oKey)
		pKey, err := kStore.GetPublicKey(extraKID2)
		assert.NoError(t, err)
		assert.Same(t, &key5.PublicKey, pKey)
		aKey, err := kStore.GetPublicKey("key1")
		assert.NoError(t, err)
		assert.NotNil(t, aKey)
		bKey, err := kStore.GetPublicKey("key2")
		assert.NoError(t, err)
		assert.NotNil(t, bKey)
		cKey, err := kStore.GetPublicKey("key3")
		assert.NoError(t, err)
		assert.NotNil(t, cKey)
		wKey, err := kStore.GetPublicKey("key1337")
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrMissingPublicKey)
		assert.Nil(t, wKey)
	})

	t.Run("TestRemoveKey", func(t *testing.T) {
		kStore.RemoveKey(extraKID1)
		assert.NotContains(t, kStore.ListKeys(), extraKID1)
		oKey1, err := kStore.GetPrivateKey(extraKID1)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrMissingPrivateKey)
		assert.Nil(t, oKey1)
		oKey2, err := kStore.GetPublicKey(extraKID1)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrMissingPublicKey)
		assert.Nil(t, oKey2)
	})

	t.Run("TestClearKeys", func(t *testing.T) {
		kStore.ClearKeys()
		assert.Empty(t, kStore.ListKeys())
	})
}

func TestNewMJwtKeyStoreFromDirectory(t *testing.T) {
	t.Parallel()

	tempDir := setupTestDirKeyStore(t, true)

	kStore, err := NewKeyStoreFromDir(tempDir)
	assert.NoError(t, err)

	assert.Len(t, kStore.ListKeys(), 3)
	kIDsToFind := []string{"key1", "key2", "key3"}
	for _, k := range kIDsToFind {
		assert.Contains(t, kStore.ListKeys(), k)
	}
	assert.True(t, kStore.HasPrivateKey("key1"))
	assert.True(t, kStore.HasPublicKey("key1")) // loading a private key also loads the public key
	assert.True(t, kStore.HasPrivateKey("key2"))
	assert.True(t, kStore.HasPublicKey("key2"))
	assert.False(t, kStore.HasPrivateKey("key3"))
	assert.True(t, kStore.HasPublicKey("key3"))

	commonSubTestsKeyStore(t, kStore)
}

func TestExportKeyStore(t *testing.T) {
	t.Parallel()

	tempDir := setupTestDirKeyStore(t, true)
	tempDir2 := setupTestDirKeyStore(t, false)

	kStore, err := NewKeyStoreFromDir(tempDir)
	assert.NoError(t, err)

	// internally swap directory
	kStore.dir = tempDir2

	err = kStore.SaveKeys()
	assert.NoError(t, err)

	kStore2, err := NewKeyStoreFromDir(tempDir2)
	assert.NoError(t, err)

	kidList1 := kStore.ListKeys()
	kidList2 := kStore2.ListKeys()
	sort.Strings(kidList1)
	sort.Strings(kidList2)
	assert.Equal(t, kidList1, kidList2)

	commonSubTestsKeyStore(t, kStore2)
}
