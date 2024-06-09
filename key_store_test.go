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

const kst_prvExt = "prv"
const kst_pubExt = "pub"

func setupTestDirKeyStore(t *testing.T, genKeys bool) (string, func(t *testing.T)) {
	tempDir, err := os.MkdirTemp("", "this-is-a-test-dir")
	assert.NoError(t, err)

	if genKeys {
		key1, err := rsa.GenerateKey(rand.Reader, 2048)
		assert.NoError(t, err)
		err = rsaprivate.Write(path.Join(tempDir, "key1.pem."+kst_prvExt), key1)
		assert.NoError(t, err)

		key2, err := rsa.GenerateKey(rand.Reader, 2048)
		assert.NoError(t, err)
		err = rsaprivate.Write(path.Join(tempDir, "key2.pem."+kst_prvExt), key2)
		assert.NoError(t, err)
		err = rsapublic.Write(path.Join(tempDir, "key2.pem."+kst_pubExt), &key2.PublicKey)
		assert.NoError(t, err)

		key3, err := rsa.GenerateKey(rand.Reader, 2048)
		assert.NoError(t, err)
		err = rsapublic.Write(path.Join(tempDir, "key3.pem."+kst_pubExt), &key3.PublicKey)
		assert.NoError(t, err)
	}

	return tempDir, func(t *testing.T) {
		err := os.RemoveAll(tempDir)
		assert.NoError(t, err)
	}
}

func commonSubTestsKeyStore(t *testing.T, kStore KeyStore) {
	key4, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	key5, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	const extraKID1 = "key4"
	const extraKID2 = "key5"

	t.Run("TestSetKey", func(t *testing.T) {
		kStore.SetKey(extraKID1, key4)
		assert.Contains(t, kStore.ListKeys(), extraKID1)
	})

	t.Run("TestSetKeyPublic", func(t *testing.T) {
		kStore.SetKeyPublic(extraKID2, &key5.PublicKey)
		assert.Contains(t, kStore.ListKeys(), extraKID2)
	})

	t.Run("TestGetKey", func(t *testing.T) {
		oKey := kStore.GetKey(extraKID1)
		assert.Same(t, key4, oKey)
		pKey := kStore.GetKey(extraKID2)
		assert.Nil(t, pKey)
		aKey := kStore.GetKey("key1")
		assert.NotNil(t, aKey)
		bKey := kStore.GetKey("key2")
		assert.NotNil(t, bKey)
		cKey := kStore.GetKey("key3")
		assert.Nil(t, cKey)
	})

	t.Run("TestGetKeyPublic", func(t *testing.T) {
		oKey := kStore.GetKeyPublic(extraKID1)
		assert.Same(t, &key4.PublicKey, oKey)
		pKey := kStore.GetKeyPublic(extraKID2)
		assert.Same(t, &key5.PublicKey, pKey)
		aKey := kStore.GetKeyPublic("key1")
		assert.NotNil(t, aKey)
		bKey := kStore.GetKeyPublic("key2")
		assert.NotNil(t, bKey)
		cKey := kStore.GetKeyPublic("key3")
		assert.NotNil(t, cKey)
	})

	t.Run("TestRemoveKey", func(t *testing.T) {
		kStore.RemoveKey(extraKID1)
		assert.NotContains(t, kStore.ListKeys(), extraKID1)
		oKey1 := kStore.GetKey(extraKID1)
		assert.Nil(t, oKey1)
		oKey2 := kStore.GetKeyPublic(extraKID1)
		assert.Nil(t, oKey2)
	})

	t.Run("TestClearKeys", func(t *testing.T) {
		kStore.ClearKeys()
		assert.Empty(t, kStore.ListKeys())
	})
}

func TestNewMJwtKeyStoreFromDirectory(t *testing.T) {
	t.Parallel()

	tempDir, cleaner := setupTestDirKeyStore(t, true)
	defer cleaner(t)

	kStore, err := NewMJwtKeyStoreFromDirectory(tempDir, kst_prvExt, kst_pubExt)
	assert.NoError(t, err)

	assert.Len(t, kStore.ListKeys(), 3)
	kIDsToFind := []string{"key1", "key2", "key3"}
	for _, k := range kIDsToFind {
		assert.Contains(t, kStore.ListKeys(), k)
	}

	commonSubTestsKeyStore(t, kStore)
}

func TestExportKeyStore(t *testing.T) {
	t.Parallel()

	tempDir, cleaner := setupTestDirKeyStore(t, true)
	defer cleaner(t)
	tempDir2, cleaner2 := setupTestDirKeyStore(t, false)
	defer cleaner2(t)

	kStore, err := NewMJwtKeyStoreFromDirectory(tempDir, kst_prvExt, kst_pubExt)
	assert.NoError(t, err)

	const prvExt2 = "v"
	const pubExt2 = "b"

	err = ExportKeyStore(kStore, tempDir2, prvExt2, pubExt2)
	assert.NoError(t, err)

	kStore2, err := NewMJwtKeyStoreFromDirectory(tempDir2, prvExt2, pubExt2)
	assert.NoError(t, err)

	kIDsToFind := kStore.ListKeys()
	assert.Len(t, kStore2.ListKeys(), len(kIDsToFind))
	for _, k := range kIDsToFind {
		assert.Contains(t, kStore2.ListKeys(), k)
	}

	commonSubTestsKeyStore(t, kStore2)
}
