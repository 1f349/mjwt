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
	Issuer() string
	PrivateKey() *rsa.PrivateKey
}

// Verifier is used to verify the validity MJWT tokens and extract the claim values.
type Verifier interface {
	VerifyJwt(token string, claims baseTypeClaim) (*jwt.Token, error)
	PublicKey() *rsa.PublicKey
}
