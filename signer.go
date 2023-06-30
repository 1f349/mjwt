package mjwt

import (
	"crypto/rsa"
	"crypto/x509"
	"github.com/golang-jwt/jwt/v4"
	"io"
	"os"
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

// NewMJwtSignerFromFileOrCreate creates a new defaultMJwtSigner using the path
// of a rsa.PrivateKey file. If the file does not exist then the file is created
// and a new private key is generated.
func NewMJwtSignerFromFileOrCreate(issuer, file string, random io.Reader, bits int) (Signer, error) {
	privateKey, err := readOrCreatePrivateKey(file, random, bits)
	if err != nil {
		return nil, err
	}
	return NewMJwtSigner(issuer, privateKey), nil
}

// NewMJwtSignerFromFile creates a new defaultMJwtSigner using the path of a
// rsa.PrivateKey file.
func NewMJwtSignerFromFile(issuer, file string) (Signer, error) {
	raw, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	key, err := x509.ParsePKCS1PrivateKey(raw)
	if err != nil {
		return nil, err
	}
	return NewMJwtSigner(issuer, key), nil
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

// readOrCreatePrivateKey returns the private key it the file already exists,
// generates a new private key and saves it to the file, or returns an error if
// reading or generating failed.
func readOrCreatePrivateKey(file string, random io.Reader, bits int) (*rsa.PrivateKey, error) {
	// read the file or return nil
	f, err := readOrEmptyFile(file)
	if err != nil {
		return nil, err
	}
	if f == nil {
		// generate a new key
		key, err := rsa.GenerateKey(random, bits)
		if err != nil {
			return nil, err
		}

		// write the key to the file
		err = os.WriteFile(file, x509.MarshalPKCS1PrivateKey(key), 0600)
		return key, err
	} else {
		// try to parse the private key
		return x509.ParsePKCS1PrivateKey(f)
	}
}

// readOrEmptyFile returns bytes and errors from os.ReadFile or (nil, nil) if the
// file does not exist.
func readOrEmptyFile(file string) ([]byte, error) {
	raw, err := os.ReadFile(file)
	if err == nil {
		return raw, nil
	}
	if os.IsNotExist(err) {
		return nil, nil
	}
	return nil, err
}
