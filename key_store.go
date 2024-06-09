package mjwt

import (
	"crypto/rsa"
	"errors"
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
func NewMJwtKeyStoreFromDirectory(directory, keyPrvExt, keyPubExt string) (KeyStore, error) {
	// Create empty KeyStore
	ks := NewMJwtKeyStore().(*defaultMJwtKeyStore)
	// List directory contents
	dirEntries, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	errs := make([]error, 0, len(dirEntries)/2)
	// Import keys from files, based on extension
	for _, entry := range dirEntries {
		if entry.IsDir() {
			continue
		}
		kID, _, _ := strings.Cut(entry.Name(), ".")
		if kID == "" {
			continue
		}
		pExt := path.Ext(entry.Name())
		if pExt == "."+keyPrvExt {
			// Load rsa private key with the file name as the kID (Up to the first .)
			key, err2 := rsaprivate.Read(path.Join(directory, entry.Name()))
			if err2 == nil {
				ks.store[kID] = key
				ks.storePub[kID] = &key.PublicKey
			}
			errs = append(errs, err2)
		} else if pExt == "."+keyPubExt {
			// Load rsa public key with the file name as the kID (Up to the first .)
			key, err2 := rsapublic.Read(path.Join(directory, entry.Name()))
			if err2 == nil {
				_, exs := ks.store[kID]
				if !exs {
					ks.store[kID] = nil
				}
				ks.storePub[kID] = key
			}
			errs = append(errs, err2)
		}
	}
	return ks, errors.Join(errs...)
}

// ExportKeyStore saves all the keys stored in the specified KeyStore into a directory with the specified
// extensions for public and private keys
func ExportKeyStore(ks KeyStore, directory, keyPrvExt, keyPubExt string) error {
	if ks == nil {
		return errors.New("ks is nil")
	}

	// Create directory
	err := os.MkdirAll(directory, 0700)
	if err != nil {
		return err
	}

	errs := make([]error, 0, len(ks.ListKeys())/2)
	// Export all keys
	for _, kID := range ks.ListKeys() {
		kPrv := ks.GetKey(kID)
		if kPrv != nil {
			err2 := rsaprivate.Write(path.Join(directory, kID+"."+keyPrvExt), kPrv)
			errs = append(errs, err2)
		}
		kPub := ks.GetKeyPublic(kID)
		if kPub != nil {
			err2 := rsapublic.Write(path.Join(directory, kID+"."+keyPubExt), kPub)
			errs = append(errs, err2)
		}
	}
	return errors.Join(errs...)
}

// SetKey adds a new rsa.PrivateKey with the specified kID to the KeyStore.
func (d *defaultMJwtKeyStore) SetKey(kID string, prvKey *rsa.PrivateKey) {
	if d == nil || prvKey == nil {
		return
	}
	d.rwLocker.Lock()
	defer d.rwLocker.Unlock()
	d.store[kID] = prvKey
	d.storePub[kID] = &prvKey.PublicKey
	return
}

// SetKeyPublic adds a new rsa.PublicKey with the specified kID to the KeyStore.
func (d *defaultMJwtKeyStore) SetKeyPublic(kID string, pubKey *rsa.PublicKey) {
	if d == nil || pubKey == nil {
		return
	}
	d.rwLocker.Lock()
	defer d.rwLocker.Unlock()
	_, exs := d.store[kID]
	if !exs {
		d.store[kID] = nil
	}
	d.storePub[kID] = pubKey
	return
}

// RemoveKey removes a specified kID from the KeyStore.
func (d *defaultMJwtKeyStore) RemoveKey(kID string) {
	if d == nil {
		return
	}
	d.rwLocker.Lock()
	defer d.rwLocker.Unlock()
	delete(d.store, kID)
	delete(d.storePub, kID)
	return
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
		i++
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
	clear(d.store)
	clear(d.storePub)
}
