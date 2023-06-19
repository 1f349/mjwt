package mjwt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
	"time"
)

func TestNewMJwtVerifierFromFile(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	s := NewMJwtSigner("mjwt.test", key)
	token, err := s.GenerateJwt("1", "test", 10*time.Minute, testClaims{TestValue: "world"})
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
