package mjwt

import (
	"crypto/rsa"
	"errors"
	"github.com/1f349/rsa-helper/rsaprivate"
	"github.com/1f349/rsa-helper/rsapublic"
	"github.com/golang-jwt/jwt/v4"
	"github.com/spf13/afero"
	"golang.org/x/sync/errgroup"
	"io/fs"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

var ErrMissingPrivateKey = errors.New("missing private key")
var ErrMissingPublicKey = errors.New("missing public key")
var ErrMissingKeyPair = errors.New("missing key pair")

const PrivateStr = ".private"
const PublicStr = ".public"

const PemExt = ".pem"
const PrivatePemExt = PrivateStr + PemExt
const PublicPemExt = PublicStr + PemExt

type KeyStore struct {
	mu    *sync.RWMutex
	store map[string]*keyPair
	dir   afero.Fs
}

func NewKeyStore() *KeyStore {
	return &KeyStore{
		mu:    new(sync.RWMutex),
		store: make(map[string]*keyPair),
	}
}

func NewKeyStoreWithDir(dir afero.Fs) *KeyStore {
	keyStore := NewKeyStore()
	keyStore.dir = dir
	return keyStore
}

func NewKeyStoreFromDir(dir afero.Fs) (*KeyStore, error) {
	keyStore := NewKeyStoreWithDir(dir)
	err := afero.Walk(dir, ".", func(path string, d fs.FileInfo, err error) error {
		// maybe this is "name.private.pem"
		name := filepath.Base(path)
		ext := filepath.Ext(name)
		if ext != PemExt {
			return nil
		}

		name = strings.TrimSuffix(name, ext)
		ext = filepath.Ext(name)
		name = strings.TrimSuffix(name, ext)
		switch ext {
		case PrivateStr:
			open, err := dir.Open(path)
			if err != nil {
				return err
			}
			decode, err := rsaprivate.Decode(open)
			if err != nil {
				return err
			}
			keyStore.LoadPrivateKey(name, decode)
			return nil
		case PublicStr:
			open, err := dir.Open(path)
			if err != nil {
				return err
			}
			decode, err := rsapublic.Decode(open)
			if err != nil {
				return err
			}
			keyStore.LoadPublicKey(name, decode)
			return nil
		}

		// still invalid
		return nil
	})
	return keyStore, err
}

type keyPair struct {
	private *rsa.PrivateKey
	public  *rsa.PublicKey
}

func (k *KeyStore) LoadPrivateKey(kid string, key *rsa.PrivateKey) {
	k.mu.Lock()
	if k.store[kid] == nil {
		k.store[kid] = &keyPair{}
	}
	k.store[kid].private = key
	k.store[kid].public = &key.PublicKey
	k.mu.Unlock()
}

func (k *KeyStore) LoadPublicKey(kid string, key *rsa.PublicKey) {
	k.mu.Lock()
	if k.store[kid] == nil {
		k.store[kid] = &keyPair{}
	}
	k.store[kid].public = key
	k.mu.Unlock()
}

func (k *KeyStore) RemoveKey(kid string) {
	k.mu.Lock()
	delete(k.store, kid)
	k.mu.Unlock()
}

func (k *KeyStore) ListKeys() []string {
	k.mu.RLock()
	defer k.mu.RUnlock()
	keys := make([]string, 0, len(k.store))
	for k, _ := range k.store {
		keys = append(keys, k)
	}
	return keys
}

func (k *KeyStore) GetPrivateKey(kid string) (*rsa.PrivateKey, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if !k.internalHasPrivateKey(kid) {
		return nil, ErrMissingPrivateKey
	}
	return k.store[kid].private, nil
}

func (k *KeyStore) GetPublicKey(kid string) (*rsa.PublicKey, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if !k.internalHasPublicKey(kid) {
		return nil, ErrMissingPublicKey
	}
	return k.store[kid].public, nil
}

func (k *KeyStore) ClearKeys() {
	k.mu.Lock()
	clear(k.store)
	k.mu.Unlock()
}

func (k *KeyStore) HasPrivateKey(kid string) bool {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.internalHasPrivateKey(kid)
}

func (k *KeyStore) internalHasPrivateKey(kid string) bool {
	v := k.store[kid]
	return v != nil && v.private != nil
}

func (k *KeyStore) HasPublicKey(kid string) bool {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.internalHasPublicKey(kid)
}

func (k *KeyStore) internalHasPublicKey(kid string) bool {
	v := k.store[kid]
	return v != nil && v.public != nil
}

func (k *KeyStore) VerifyJwt(token string, claims baseTypeClaim) (*jwt.Token, error) {
	withClaims, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, ErrMissingPublicKey
		}
		return k.GetPublicKey(kid)
	})
	if err != nil {
		return nil, err
	}
	return withClaims, claims.Valid()
}

func (k *KeyStore) SaveSingleKey(kid string) error {
	if k.dir == nil {
		return nil
	}

	k.mu.RLock()
	pair := k.store[kid]
	k.mu.RUnlock()
	if pair == nil {
		return ErrMissingKeyPair
	}

	var errs []error
	if pair.private != nil {
		errs = append(errs, afero.WriteFile(k.dir, kid+PrivatePemExt, rsaprivate.Encode(pair.private), 0600))
	}
	if pair.public != nil {
		errs = append(errs, afero.WriteFile(k.dir, kid+PublicPemExt, rsapublic.Encode(pair.public), 0600))
	}
	return errors.Join(errs...)
}

func (k *KeyStore) SaveKeys() error {
	k.mu.RLock()
	defer k.mu.RUnlock()

	workers := new(errgroup.Group)
	workers.SetLimit(runtime.NumCPU())
	for kid, pair := range k.store {
		workers.Go(func() error {
			var errs []error
			if pair.private != nil {
				errs = append(errs, afero.WriteFile(k.dir, kid+PrivatePemExt, rsaprivate.Encode(pair.private), 0600))
			}
			if pair.public != nil {
				errs = append(errs, afero.WriteFile(k.dir, kid+PublicPemExt, rsapublic.Encode(pair.public), 0600))
			}
			return errors.Join(errs...)
		})
	}
	return workers.Wait()
}
