package mjwt

import (
	"crypto/rsa"
	"github.com/golang-jwt/jwt/v4"
	"time"
)

// defaultMJwtSigner implements Signer and uses an rsa.PrivateKey and issuer name
// to generate MJWT tokens
type defaultMJwtSigner struct {
	issuer string
	key    *rsa.PrivateKey
	verify *defaultMJwtVerifier
}

var _ Signer = &defaultMJwtSigner{}

// NewMJwtSigner creates a new defaultMJwtSigner using the issuer name and rsa.PrivateKey
func NewMJwtSigner(issuer string, key *rsa.PrivateKey) Signer {
	return &defaultMJwtSigner{
		issuer: issuer,
		key:    key,
		verify: newMJwtVerifier(&key.PublicKey),
	}
}

// Issuer returns the name of the issuer
func (d *defaultMJwtSigner) Issuer() string { return d.issuer }

// GenerateJwt generates and returns a JWT string using the sub, id, duration and claims
func (d *defaultMJwtSigner) GenerateJwt(sub, id string, aud jwt.ClaimStrings, dur time.Duration, claims Claims) (string, error) {
	return d.SignJwt(wrapClaims[Claims](d, sub, id, aud, dur, claims))
}

// SignJwt signs a jwt.Claims compatible struct, this is used internally by
// GenerateJwt but is available for signing custom structs
func (d *defaultMJwtSigner) SignJwt(wrapped jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS512, wrapped)
	return token.SignedString(d.key)
}

// VerifyJwt validates and parses MJWT tokens see defaultMJwtVerifier.VerifyJwt()
func (d *defaultMJwtSigner) VerifyJwt(token string, claims baseTypeClaim) (*jwt.Token, error) {
	return d.verify.VerifyJwt(token, claims)
}
