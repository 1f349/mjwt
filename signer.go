package mjwt

import (
	"bytes"
	"crypto/rsa"
	"errors"
	"github.com/1f349/rsa-helper/rsaprivate"
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
var _ Verifier = &defaultMJwtSigner{}

// NewMJwtSigner creates a new defaultMJwtSigner using the issuer name and rsa.PrivateKey
func NewMJwtSigner(issuer string, key *rsa.PrivateKey) Signer {
	return NewMJwtSignerWithKeyStore(issuer, key, NewMJwtKeyStore())
}

// NewMJwtSignerWithKeyStore creates a new defaultMJwtSigner using the issuer name, a rsa.PrivateKey
// for no kID and a KeyStore for kID based keys
func NewMJwtSignerWithKeyStore(issuer string, key *rsa.PrivateKey, kStore KeyStore) Signer {
	return &defaultMJwtSigner{
		issuer: issuer,
		key:    key,
		verify: NewMjwtVerifierWithKeyStore(&key.PublicKey, kStore).(*defaultMJwtVerifier),
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
	return NewMJwtSignerFromFileAndDirectory(issuer, file, "", "", "")
}

// NewMJwtSignerFromDirectory creates a new defaultMJwtSigner using the path of a directory to
// load the keys into a KeyStore; there is no default rsa.PrivateKey
func NewMJwtSignerFromDirectory(issuer, directory, prvExt, pubExt string) (Signer, error) {
	return NewMJwtSignerFromFileAndDirectory(issuer, "", directory, prvExt, pubExt)
}

// NewMJwtSignerFromFileAndDirectory creates a new defaultMJwtSigner using the path of a rsa.PrivateKey
// file as the non kID key and the path of a directory to load the keys into a KeyStore
func NewMJwtSignerFromFileAndDirectory(issuer, file, directory, prvExt, pubExt string) (Signer, error) {
	var err error

	// read key
	var prv *rsa.PrivateKey = nil
	if file != "" {
		prv, err = rsaprivate.Read(file)
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

	return NewMJwtSignerWithKeyStore(issuer, prv, kStore), nil
}

// Issuer returns the name of the issuer
func (d *defaultMJwtSigner) Issuer() string {
	if d == nil {
		return ""
	}
	return d.issuer
}

// GenerateJwt generates and returns a JWT string using the sub, id, duration and claims; uses the default key
func (d *defaultMJwtSigner) GenerateJwt(sub, id string, aud jwt.ClaimStrings, dur time.Duration, claims Claims) (string, error) {
	if d == nil {
		return "", errors.New("signer nil")
	}
	return d.SignJwt(wrapClaims[Claims](d, sub, id, aud, dur, claims))
}

// SignJwt signs a jwt.Claims compatible struct, this is used internally by
// GenerateJwt but is available for signing custom structs; uses the default key
func (d *defaultMJwtSigner) SignJwt(wrapped jwt.Claims) (string, error) {
	if d == nil {
		return "", errors.New("signer nil")
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS512, wrapped)
	return token.SignedString(d.key)
}

// GenerateJwtWithKID generates and returns a JWT string using the sub, id, duration and claims; this gets signed with the specified kID
func (d *defaultMJwtSigner) GenerateJwtWithKID(sub, id string, aud jwt.ClaimStrings, dur time.Duration, claims Claims, kID string) (string, error) {
	if d == nil {
		return "", errors.New("signer nil")
	}
	return d.SignJwtWithKID(wrapClaims[Claims](d, sub, id, aud, dur, claims), kID)
}

// SignJwtWithKID signs a jwt.Claims compatible struct, this is used internally by
// GenerateJwt but is available for signing custom structs; this gets signed with the specified kID
func (d *defaultMJwtSigner) SignJwtWithKID(wrapped jwt.Claims, kID string) (string, error) {
	if d == nil {
		return "", errors.New("signer nil")
	}
	pKey := d.verify.GetKeyStore().GetKey(kID)
	if pKey == nil {
		return "", errors.New("no private key found")
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS512, wrapped)
	token.Header["kid"] = kID
	return token.SignedString(pKey)
}

// VerifyJwt validates and parses MJWT tokens see defaultMJwtVerifier.VerifyJwt()
func (d *defaultMJwtSigner) VerifyJwt(token string, claims baseTypeClaim) (*jwt.Token, error) {
	if d == nil {
		return nil, errors.New("signer nil")
	}
	return d.verify.VerifyJwt(token, claims)
}

func (d *defaultMJwtSigner) PrivateKey() *rsa.PrivateKey {
	if d == nil {
		return nil
	}
	return d.key
}
func (d *defaultMJwtSigner) PublicKey() *rsa.PublicKey {
	if d == nil {
		return nil
	}
	return d.verify.pub
}

func (d *defaultMJwtSigner) PublicKeyOf(kID string) *rsa.PublicKey {
	if d == nil {
		return nil
	}
	return d.verify.kStore.GetKeyPublic(kID)
}

func (d *defaultMJwtSigner) GetKeyStore() KeyStore {
	if d == nil {
		return nil
	}
	return d.verify.GetKeyStore()
}

func (d *defaultMJwtSigner) PrivateKeyOf(kID string) *rsa.PrivateKey {
	if d == nil {
		return nil
	}
	return d.verify.kStore.GetKey(kID)
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

		// save key to file
		err = rsaprivate.Write(file, key)
		if err != nil {
			return nil, err
		}
		return key, err
	} else {
		// return key
		return rsaprivate.Decode(bytes.NewReader(f))
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
