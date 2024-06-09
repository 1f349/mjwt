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
	"time"
)

const vt_prvExt = "prv"
const vt_pubExt = "pub"

func setupTestDirVerifier(t *testing.T, genKeys bool) (string, *rsa.PrivateKey, func(t *testing.T)) {
	tempDir, err := os.MkdirTemp("", "this-is-a-test-dir")
	assert.NoError(t, err)

	var key3 *rsa.PrivateKey = nil

	if genKeys {
		key1, err := rsa.GenerateKey(rand.Reader, 2048)
		assert.NoError(t, err)
		err = rsaprivate.Write(path.Join(tempDir, "key1.pem."+vt_prvExt), key1)
		assert.NoError(t, err)

		key2, err := rsa.GenerateKey(rand.Reader, 2048)
		assert.NoError(t, err)
		err = rsaprivate.Write(path.Join(tempDir, "key2.pem."+vt_prvExt), key2)
		assert.NoError(t, err)
		err = rsapublic.Write(path.Join(tempDir, "key2.pem."+vt_pubExt), &key2.PublicKey)
		assert.NoError(t, err)

		key3, err = rsa.GenerateKey(rand.Reader, 2048)
		assert.NoError(t, err)
		err = rsapublic.Write(path.Join(tempDir, "key3.pem."+vt_pubExt), &key3.PublicKey)
		assert.NoError(t, err)
	}

	return tempDir, key3, func(t *testing.T) {
		err := os.RemoveAll(tempDir)
		assert.NoError(t, err)
	}
}

func TestNewMJwtVerifierFromFile(t *testing.T) {
	t.Parallel()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	s := NewMJwtSigner("mjwt.test", key)
	token, err := s.GenerateJwt("1", "test", nil, 10*time.Minute, testClaims{TestValue: "world"})
	assert.NoError(t, err)

	b := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&key.PublicKey)})
	temp, err := os.CreateTemp("", "this-is-a-test-file.pem")
	assert.NoError(t, err)
	_, err = temp.Write(b)
	assert.NoError(t, err)
	file, err := NewMJwtVerifierFromFile(temp.Name())
	assert.NoError(t, err)
	_, _, err = ExtractClaims[testClaims](file, token)
	assert.NoError(t, err)
	err = os.Remove(temp.Name())
	assert.NoError(t, err)
}

func TestNewMJwtVerifierFromDirectory(t *testing.T) {
	t.Parallel()

	tempDir, prvKey3, cleaner := setupTestDirVerifier(t, true)
	defer cleaner(t)

	s, err := NewMJwtSignerFromDirectory("mjwt.test", tempDir, vt_prvExt, vt_pubExt)
	assert.NoError(t, err)
	s.GetKeyStore().SetKey("key3", prvKey3)
	token, err := s.GenerateJwtWithKID("1", "test", nil, 10*time.Minute, testClaims{TestValue: "world"}, "key3")
	assert.NoError(t, err)

	v, err := NewMJwtVerifierFromDirectory(tempDir, vt_prvExt, vt_pubExt)
	assert.NoError(t, err)
	_, _, err = ExtractClaims[testClaims](v, token)
	assert.NoError(t, err)
}

func TestNewMJwtVerifierFromFileAndDirectory(t *testing.T) {
	t.Parallel()

	tempDir, prvKey3, cleaner := setupTestDirVerifier(t, true)
	defer cleaner(t)

	s, err := NewMJwtSignerFromFileAndDirectory("mjwt.test", path.Join(tempDir, "key2.pem."+vt_prvExt), tempDir, vt_prvExt, vt_pubExt)
	assert.NoError(t, err)
	s.GetKeyStore().SetKey("key3", prvKey3)
	token1, err := s.GenerateJwt("1", "test", nil, 10*time.Minute, testClaims{TestValue: "world"})
	assert.NoError(t, err)
	token2, err := s.GenerateJwtWithKID("1", "test", nil, 10*time.Minute, testClaims{TestValue: "world"}, "key3")
	assert.NoError(t, err)

	v, err := NewMJwtVerifierFromFileAndDirectory(path.Join(tempDir, "key2.pem."+vt_pubExt), tempDir, vt_prvExt, vt_pubExt)
	assert.NoError(t, err)
	_, _, err = ExtractClaims[testClaims](v, token1)
	assert.NoError(t, err)
	_, _, err = ExtractClaims[testClaims](v, token2)
	assert.NoError(t, err)
}
