package mjwt

import (
	"crypto/rsa"
	"errors"
	"github.com/1f349/rsa-helper/rsapublic"
	"github.com/golang-jwt/jwt/v4"
)

// defaultMJwtVerifier implements Verifier and uses a rsa.PublicKey to validate
// MJWT tokens
type defaultMJwtVerifier struct {
	pub    *rsa.PublicKey
	kStore KeyStore
}

var _ Verifier = &defaultMJwtVerifier{}

// NewMJwtVerifier creates a new defaultMJwtVerifier using the rsa.PublicKey
func NewMJwtVerifier(key *rsa.PublicKey) Verifier {
	return NewMjwtVerifierWithKeyStore(key, NewMJwtKeyStore())
}

// NewMjwtVerifierWithKeyStore creates a new defaultMJwtVerifier using a rsa.PublicKey as the non kID key
// and a KeyStore for kID based keys
func NewMjwtVerifierWithKeyStore(defaultKey *rsa.PublicKey, kStore KeyStore) Verifier {
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

	return NewMjwtVerifierWithKeyStore(pub, kStore), nil
}

// VerifyJwt validates and parses MJWT tokens and returns the claims
func (d *defaultMJwtVerifier) VerifyJwt(token string, claims baseTypeClaim) (*jwt.Token, error) {
	if d == nil {
		return nil, errors.New("verifier nil")
	}
	withClaims, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		kIDI, exs := token.Header["kid"]
		if exs {
			kID, ok := kIDI.(string)
			if ok {
				key := d.kStore.GetKeyPublic(kID)
				if key == nil {
					return nil, errors.New("no public key found")
				} else {
					return key, nil
				}
			} else {
				return nil, errors.New("kid invalid")
			}
		}
		if d.pub == nil {
			return nil, errors.New("no public key found")
		}
		return d.pub, nil
	})
	if err != nil {
		return nil, err
	}
	return withClaims, claims.Valid()
}

func (d *defaultMJwtVerifier) PublicKey() *rsa.PublicKey {
	if d == nil {
		return nil
	}
	return d.pub
}

func (d *defaultMJwtVerifier) PublicKeyOf(kID string) *rsa.PublicKey {
	if d == nil {
		return nil
	}
	return d.kStore.GetKeyPublic(kID)
}

func (d *defaultMJwtVerifier) GetKeyStore() KeyStore {
	if d == nil {
		return nil
	}
	return d.kStore
}
