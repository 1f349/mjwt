package mjwt

import (
	"crypto/rsa"
	"github.com/golang-jwt/jwt/v4"
	"time"
)

// Signer is used to generate MJWT tokens.
// Signer can also be used as a Verifier.
type Signer interface {
	Verifier
	GenerateJwt(sub, id string, aud jwt.ClaimStrings, dur time.Duration, claims Claims) (string, error)
	SignJwt(claims jwt.Claims) (string, error)
	GenerateJwtWithKID(sub, id string, aud jwt.ClaimStrings, dur time.Duration, claims Claims, kID string) (string, error)
	SignJwtWithKID(claims jwt.Claims, kID string) (string, error)
	Issuer() string
	PrivateKey() *rsa.PrivateKey
	PrivateKeyOf(kID string) *rsa.PrivateKey
}

// Verifier is used to verify the validity MJWT tokens and extract the claim values.
type Verifier interface {
	VerifyJwt(token string, claims baseTypeClaim) (*jwt.Token, error)
	PublicKey() *rsa.PublicKey
	PublicKeyOf(kID string) *rsa.PublicKey
	GetKeyStore() KeyStore
}

// KeyStore is used for the kid header support in Signer and Verifier.
type KeyStore interface {
	SetKey(kID string, prvKey *rsa.PrivateKey)
	SetKeyPublic(kID string, pubKey *rsa.PublicKey)
	RemoveKey(kID string)
	ListKeys() []string
	GetKey(kID string) *rsa.PrivateKey
	GetKeyPublic(kID string) *rsa.PublicKey
	ClearKeys()
}
