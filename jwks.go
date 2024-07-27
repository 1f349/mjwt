package mjwt

import (
	"encoding/json"
	"github.com/go-jose/go-jose/v4"
	"io"
)

func WriteJwkSetJson(w io.Writer, issuers []*Issuer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	var j jose.JSONWebKeySet
	for _, issuer := range issuers {
		// get public key from private key
		key, err := issuer.PrivateKey()
		if err != nil {
			return err
		}
		pubKey := &key.PublicKey

		// format as JWK
		j.Keys = append(j.Keys, jose.JSONWebKey{
			Algorithm: issuer.signing.Alg(),
			Use:       "sig",
			KeyID:     issuer.kid,
			Key:       pubKey,
		})
	}
	return enc.Encode(j)
}
