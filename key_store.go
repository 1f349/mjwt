package mjwt

import (
	"crypto/rsa"
	"github.com/1f349/rsa-helper/rsaprivate"
	"github.com/1f349/rsa-helper/rsapublic"
	"os"
	"path"
	"strings"
	"sync"
)

// defaultMJwtKeyStore implements KeyStore and stores kIDs against just rsa.PublicKey
// or with rsa.PrivateKey instances as well.
type defaultMJwtKeyStore struct {
	rwLocker *sync.RWMutex
	store    map[string]*rsa.PrivateKey
	storePub map[string]*rsa.PublicKey
}

var _ KeyStore = &defaultMJwtKeyStore{}

// NewMJwtKeyStore creates a new defaultMJwtKeyStore.
func NewMJwtKeyStore() KeyStore {
	return &defaultMJwtKeyStore{
		rwLocker: new(sync.RWMutex),
		store:    make(map[string]*rsa.PrivateKey),
		storePub: make(map[string]*rsa.PublicKey),
	}
}

// NewMJwtKeyStoreFromDirectory loads keys from a directory with the specified extensions to denote public and private
// rsa keys; the kID is the filename of the key up to the first .
func NewMJwtKeyStoreFromDirectory(directory string, keyPrvExt string, keyPubExt string) (KeyStore, error) {
	// Create empty KeyStore
	ks := NewMJwtKeyStore()
	// List directory contents
	dirEntries, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	// Import keys from files, based on extension
	for _, entry := range dirEntries {
		if !entry.IsDir() {
			firstDotIdx := strings.Index(entry.Name(), ".")
			lastDotIdx := strings.LastIndex(entry.Name(), ".")
			if firstDotIdx > 0 && lastDotIdx+1 < len(entry.Name()) {
				if entry.Name()[lastDotIdx+1:] == keyPrvExt {
					// Load rsa private key with the file name as the kID (Up to the first .)
					key, err := rsaprivate.Read(path.Join(directory, entry.Name()))
					if err == nil {
						ks.SetKey(entry.Name()[:firstDotIdx], key)
					}
				} else if entry.Name()[lastDotIdx+1:] == keyPubExt {
					// Load rsa public key with the file name as the kID (Up to the first .)
					key, err := rsapublic.Read(path.Join(directory, entry.Name()))
					if err == nil {
						ks.SetKeyPublic(entry.Name()[:firstDotIdx], key)
					}
				}
			}
		}
	}
	return ks, nil
}

// SetKey adds a new rsa.PrivateKey with the specified kID to the KeyStore.
func (d *defaultMJwtKeyStore) SetKey(kID string, prvKey *rsa.PrivateKey) bool {
	if d == nil || prvKey == nil {
		return false
	}
	d.rwLocker.Lock()
	defer d.rwLocker.Unlock()
	d.store[kID] = prvKey
	d.storePub[kID] = &prvKey.PublicKey
	return true
}

// SetKeyPublic adds a new rsa.PublicKey with the specified kID to the KeyStore.
func (d *defaultMJwtKeyStore) SetKeyPublic(kID string, pubKey *rsa.PublicKey) bool {
	if d == nil || pubKey == nil {
		return false
	}
	d.rwLocker.Lock()
	defer d.rwLocker.Unlock()
	delete(d.store, kID)
	d.storePub[kID] = pubKey
	return true
}

// RemoveKey removes a specified kID from the KeyStore.
func (d *defaultMJwtKeyStore) RemoveKey(kID string) bool {
	if d == nil {
		return false
	}
	d.rwLocker.Lock()
	defer d.rwLocker.Unlock()
	delete(d.store, kID)
	delete(d.storePub, kID)
	return true
}

// ListKeys lists the kIDs of all the keys in the KeyStore.
func (d *defaultMJwtKeyStore) ListKeys() []string {
	if d == nil {
		return nil
	}
	d.rwLocker.RLock()
	defer d.rwLocker.RUnlock()
	lKeys := make([]string, len(d.store))
	i := 0
	for k := range d.store {
		lKeys[i] = k
	}
	return lKeys
}

// GetKey gets the rsa.PrivateKey given the kID in the KeyStore or null if not found.
func (d *defaultMJwtKeyStore) GetKey(kID string) *rsa.PrivateKey {
	if d == nil {
		return nil
	}
	d.rwLocker.RLock()
	defer d.rwLocker.RUnlock()
	kPrv, ok := d.store[kID]
	if ok {
		return kPrv
	}
	return nil
}

// GetKeyPublic gets the rsa.PublicKey given the kID in the KeyStore or null if not found.
func (d *defaultMJwtKeyStore) GetKeyPublic(kID string) *rsa.PublicKey {
	if d == nil {
		return nil
	}
	d.rwLocker.RLock()
	defer d.rwLocker.RUnlock()
	kPub, ok := d.storePub[kID]
	if ok {
		return kPub
	}
	return nil
}

// ClearKeys removes all the stored keys in the KeyStore.
func (d *defaultMJwtKeyStore) ClearKeys() {
	if d == nil {
		return
	}
	d.rwLocker.Lock()
	defer d.rwLocker.Unlock()
	for k := range d.store {
		delete(d.store, k)
	}
	for k := range d.storePub {
		delete(d.storePub, k)
	}
}
