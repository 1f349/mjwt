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

var _ Provider = &defaultMJwtSigner{}

func NewMJwtSigner(issuer string, key *rsa.PrivateKey) Provider {
	return &defaultMJwtSigner{
		issuer: issuer,
		key:    key,
		verify: newMJwtVerifier(&key.PublicKey),
	}
}

func (d *defaultMJwtSigner) Issuer() string { return d.issuer }

func (d *defaultMJwtSigner) GenerateJwt(sub, id string, dur time.Duration, claims Claims) (string, error) {
	wrapped := wrapClaims[Claims](d, sub, id, dur, claims)
	token := jwt.NewWithClaims(jwt.SigningMethodRS512, wrapped)
	return token.SignedString(d.key)
}

func (d *defaultMJwtSigner) VerifyJwt(token string, claims baseTypeClaim) (*jwt.Token, error) {
	return d.verify.VerifyJwt(token, claims)
}
