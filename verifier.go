package mjwt

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"github.com/golang-jwt/jwt/v4"
	"github.com/pkg/errors"
	"os"
	"time"
)

var ErrCannotGenerateMJwtToken = errors.New("cannot generate mjwt token with verifier")

type defaultMJwtVerifier struct {
	pub *rsa.PublicKey
}

var _ Provider = &defaultMJwtVerifier{}

func NewMJwtVerifier(key *rsa.PublicKey) Provider {
	return newMJwtVerifier(key)
}

func newMJwtVerifier(key *rsa.PublicKey) *defaultMJwtVerifier {
	return &defaultMJwtVerifier{pub: key}
}

func NewMJwtVerifierFromFile(file string) (Provider, error) {
	f, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(f)
	pub, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return NewMJwtVerifier(pub), nil
}

func (d *defaultMJwtVerifier) Issuer() string { return "" }

func (d *defaultMJwtVerifier) GenerateJwt(_, _ string, _ time.Duration, _ Claims) (string, error) {
	return "", ErrCannotGenerateMJwtToken
}

func (d *defaultMJwtVerifier) SignJwt(_ jwt.Claims) (string, error) {
	return "", ErrCannotGenerateMJwtToken
}

func (d *defaultMJwtVerifier) VerifyJwt(token string, claims baseTypeClaim) (*jwt.Token, error) {
	withClaims, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return d.pub, nil
	})
	if err != nil {
		return nil, err
	}
	return withClaims, claims.Valid()
}
