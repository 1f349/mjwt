package mjwt

import (
	"crypto/rsa"
	"github.com/1f349/rsa-helper/rsapublic"
	"github.com/golang-jwt/jwt/v4"
)

// defaultMJwtVerifier implements Verifier and uses a rsa.PublicKey to validate
// MJWT tokens
type defaultMJwtVerifier struct {
	pub *rsa.PublicKey
}

var _ Verifier = &defaultMJwtVerifier{}

// NewMJwtVerifier creates a new defaultMJwtVerifier using the rsa.PublicKey
func NewMJwtVerifier(key *rsa.PublicKey) Verifier {
	return newMJwtVerifier(key)
}

func newMJwtVerifier(key *rsa.PublicKey) *defaultMJwtVerifier {
	return &defaultMJwtVerifier{pub: key}
}

// NewMJwtVerifierFromFile creates a new defaultMJwtVerifier using the path of a
// rsa.PublicKey file
func NewMJwtVerifierFromFile(file string) (Verifier, error) {
	// read key
	pub, err := rsapublic.Read(file)
	if err != nil {
		return nil, err
	}

	// create verifier using rsa.PublicKey
	return NewMJwtVerifier(pub), nil
}

// VerifyJwt validates and parses MJWT tokens and returns the claims
func (d *defaultMJwtVerifier) VerifyJwt(token string, claims baseTypeClaim) (*jwt.Token, error) {
	withClaims, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return d.pub, nil
	})
	if err != nil {
		return nil, err
	}
	return withClaims, claims.Valid()
}

func (d *defaultMJwtVerifier) PublicKey() *rsa.PublicKey { return d.pub }
