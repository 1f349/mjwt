package mjwt

import (
	"crypto/rsa"
	"github.com/golang-jwt/jwt/v4"
	"time"
)

type defaultMJwtSigner struct {
	issuer string
	key    *rsa.PrivateKey
	verify *defaultMJwtVerifier
}

var _ Signer = &defaultMJwtSigner{}

func NewMJwtSigner(issuer string, key *rsa.PrivateKey) Signer {
	return &defaultMJwtSigner{
		issuer: issuer,
		key:    key,
		verify: newMJwtVerifier(&key.PublicKey),
	}
}

func (d *defaultMJwtSigner) Issuer() string { return d.issuer }

func (d *defaultMJwtSigner) GenerateJwt(sub, id string, dur time.Duration, claims Claims) (string, error) {
	return d.SignJwt(wrapClaims[Claims](d, sub, id, dur, claims))
}

func (d *defaultMJwtSigner) SignJwt(wrapped jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS512, wrapped)
	return token.SignedString(d.key)
}

func (d *defaultMJwtSigner) VerifyJwt(token string, claims baseTypeClaim) (*jwt.Token, error) {
	return d.verify.VerifyJwt(token, claims)
}
