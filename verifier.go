package mjwt

import (
	"crypto/rsa"
	"errors"
	"github.com/1f349/rsa-helper/rsapublic"
	"github.com/golang-jwt/jwt/v4"
)

var ErrNoPublicKeyFound = errors.New("no public key found")
var ErrKIDInvalid = errors.New("kid invalid")

// defaultMJwtVerifier implements Verifier and uses a rsa.PublicKey to validate
// MJWT tokens
type defaultMJwtVerifier struct {
	pub    *rsa.PublicKey
	kStore KeyStore
}

var _ Verifier = &defaultMJwtVerifier{}

// NewMJwtVerifier creates a new defaultMJwtVerifier using the rsa.PublicKey
func NewMJwtVerifier(key *rsa.PublicKey) Verifier {
	return NewMJwtVerifierWithKeyStore(key, NewMJwtKeyStore())
}

// NewMJwtVerifierWithKeyStore creates a new defaultMJwtVerifier using a rsa.PublicKey as the non kID key
// and a KeyStore for kID based keys
func NewMJwtVerifierWithKeyStore(defaultKey *rsa.PublicKey, kStore KeyStore) Verifier {
	return &defaultMJwtVerifier{pub: defaultKey, kStore: kStore}
}

// NewMJwtVerifierFromFile creates a new defaultMJwtVerifier using the path of a
// rsa.PublicKey file
func NewMJwtVerifierFromFile(file string) (Verifier, error) {
	return NewMJwtVerifierFromFileAndDirectory(file, "", "", "")
}

// NewMJwtVerifierFromDirectory creates a new defaultMJwtVerifier using the path of a directory to
// load the keys into a KeyStore; there is no default rsa.PublicKey
func NewMJwtVerifierFromDirectory(directory, prvExt, pubExt string) (Verifier, error) {
	return NewMJwtVerifierFromFileAndDirectory("", directory, prvExt, pubExt)
}

// NewMJwtVerifierFromFileAndDirectory creates a new defaultMJwtVerifier using the path of a rsa.PublicKey
// file as the non kID key and the path of a directory to load the keys into a KeyStore
func NewMJwtVerifierFromFileAndDirectory(file, directory, prvExt, pubExt string) (Verifier, error) {
	var err error

	// read key
	var pub *rsa.PublicKey = nil
	if file != "" {
		pub, err = rsapublic.Read(file)
		if err != nil {
			return nil, err
		}
	}

	// read KeyStore
	var kStore KeyStore = nil
	if directory != "" {
		kStore, err = NewMJwtKeyStoreFromDirectory(directory, prvExt, pubExt)
		if err != nil {
			return nil, err
		}
	}

	return NewMJwtVerifierWithKeyStore(pub, kStore), nil
}

// VerifyJwt validates and parses MJWT tokens and returns the claims
func (d *defaultMJwtVerifier) VerifyJwt(token string, claims baseTypeClaim) (*jwt.Token, error) {
	withClaims, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		kIDI, exs := token.Header["kid"]
		if exs {
			kID, ok := kIDI.(string)
			if !ok {
				return nil, ErrKIDInvalid
			}
			key := d.kStore.GetKeyPublic(kID)
			if key == nil {
				return nil, ErrNoPublicKeyFound
			} else {
				return key, nil
			}
		}
		if d.pub == nil {
			return nil, ErrNoPublicKeyFound
		}
		return d.pub, nil
	})
	if err != nil {
		return nil, err
	}
	return withClaims, claims.Valid()
}

func (d *defaultMJwtVerifier) PublicKey() *rsa.PublicKey {
	return d.pub
}

func (d *defaultMJwtVerifier) PublicKeyOf(kID string) *rsa.PublicKey {
	return d.kStore.GetKeyPublic(kID)
}

func (d *defaultMJwtVerifier) GetKeyStore() KeyStore {
	return d.kStore
}
