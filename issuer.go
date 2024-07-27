package mjwt

import (
	"crypto/rand"
	"crypto/rsa"
	"github.com/golang-jwt/jwt/v4"
	"time"
)

type Issuer struct {
	issuer   string
	kid      string
	signing  jwt.SigningMethod
	keystore *KeyStore
}

func NewIssuer(name, kid string, signing jwt.SigningMethod) (*Issuer, error) {
	return NewIssuerWithKeyStore(name, kid, signing, NewKeyStore())
}

func NewIssuerWithKeyStore(name, kid string, signing jwt.SigningMethod, keystore *KeyStore) (*Issuer, error) {
	i := &Issuer{name, kid, signing, keystore}
	if i.keystore.HasPrivateKey(kid) {
		return i, nil
	}
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}
	i.keystore.LoadPrivateKey(kid, key)
	return i, i.keystore.SaveSingleKey(kid)
}

func (i *Issuer) GenerateJwt(sub, id string, aud jwt.ClaimStrings, dur time.Duration, claims Claims) (string, error) {
	return i.SignJwt(wrapClaims[Claims](sub, id, i.issuer, aud, dur, claims))
}

func (i *Issuer) SignJwt(wrapped jwt.Claims) (string, error) {
	key, err := i.PrivateKey()
	if err != nil {
		return "", err
	}
	token := jwt.NewWithClaims(i.signing, wrapped)
	token.Header["kid"] = i.kid
	return token.SignedString(key)
}

func (i *Issuer) PrivateKey() (*rsa.PrivateKey, error) {
	return i.keystore.GetPrivateKey(i.kid)
}

func (i *Issuer) KeyStore() *KeyStore {
	return i.keystore
}
