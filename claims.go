package mjwt

import (
	"encoding/json"
	"github.com/golang-jwt/jwt/v4"
	"github.com/pkg/errors"
	"time"
)

var ErrClaimTypeMismatch = errors.New("claim type mismatch")

// wrapClaims creates a BaseTypeClaims wrapper for a generic claims struct
func wrapClaims[T Claims](sub, id, issuer string, aud jwt.ClaimStrings, dur time.Duration, claims T) *BaseTypeClaims[T] {
	now := time.Now()
	return (&BaseTypeClaims[T]{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   sub,
			Audience:  aud,
			ExpiresAt: jwt.NewNumericDate(now.Add(dur)),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        id,
		},
		Claims: claims,
	}).init()
}

// ExtractClaims uses a Verifier to validate the MJWT token and returns the parsed
// token and BaseTypeClaims
func ExtractClaims[T Claims](ks *KeyStore, token string) (*jwt.Token, BaseTypeClaims[T], error) {
	b := BaseTypeClaims[T]{
		RegisteredClaims: jwt.RegisteredClaims{},
		Claims:           *new(T),
	}
	tok, err := ks.VerifyJwt(token, &b)
	return tok, b, err
}

// Claims is a wrapper for jwt.Claims and adds a Type method to name internal claim structs
type Claims interface {
	jwt.Claims
	Type() string
}

type baseTypeClaim interface {
	jwt.Claims
	InternalClaimType() string
}

// BaseTypeClaims is a wrapper for combining the jwt.RegisteredClaims with a ClaimType
// and generic Claims data
type BaseTypeClaims[T Claims] struct {
	jwt.RegisteredClaims
	ClaimType string
	Claims    T
}

func (b *BaseTypeClaims[T]) init() *BaseTypeClaims[T] {
	b.ClaimType = b.InternalClaimType()
	return b
}

// Valid checks the InternalClaimType matches and the type claim type
func (b *BaseTypeClaims[T]) Valid() error {
	if err := b.RegisteredClaims.Valid(); err != nil {
		return err
	}
	if b.ClaimType != b.InternalClaimType() {
		return ErrClaimTypeMismatch
	}
	return b.Claims.Valid()
}

// InternalClaimType returns the Type of the generic claim struct
func (b *BaseTypeClaims[T]) InternalClaimType() string { return b.Claims.Type() }

// MarshalJSON converts the internalBaseTypeClaims and generic claim struct into
// a serialized JSON byte array
func (b *BaseTypeClaims[T]) MarshalJSON() ([]byte, error) {
	// encode the internalBaseTypeClaims
	b1, err := json.Marshal(internalBaseTypeClaims{
		RegisteredClaims: b.RegisteredClaims,
		ClaimType:        b.InternalClaimType(),
	})
	if err != nil {
		return nil, err
	}

	// encode the generic claims struct
	b2, err := json.Marshal(b.Claims)
	if err != nil {
		return nil, err
	}

	// replace starting '{' with ','
	b2[0] = ','
	// join the two json strings and remove the last char '}' from the first string
	return append(b1[:len(b1)-1], b2...), nil
}

// UnmarshalJSON reads the internalBaseTypeClaims and generic claim struct from
// a serialized JSON byte array
func (b *BaseTypeClaims[T]) UnmarshalJSON(bytes []byte) error {
	a := internalBaseTypeClaims{}
	var t T

	// convert JSON to internalBaseTypeClaims
	err := json.Unmarshal(bytes, &a)
	if err != nil {
		return err
	}

	// convert JSON to the generic claim struct
	err = json.Unmarshal(bytes, &t)
	if err != nil {
		return err
	}

	// assign the fields in BaseTypeClaims
	b.RegisteredClaims = a.RegisteredClaims
	b.ClaimType = a.ClaimType
	b.Claims = t
	return err
}

// internalBaseTypeClaims is a wrapper for jwt.RegisteredClaims which adds a
// ClaimType field containing the type of the generic claim struct
type internalBaseTypeClaims struct {
	jwt.RegisteredClaims
	ClaimType string `json:"mct"`
}
