package mjwt

import (
	"bytes"
	"encoding/json"
	"github.com/golang-jwt/jwt/v4"
	"github.com/pkg/errors"
	"time"
)

var ErrClaimTypeMismatch = errors.New("claim type mismatch")

// wrapClaims creates a BaseTypeClaims wrapper for a generic claims struct
func wrapClaims[T Claims](p Signer, sub, id string, dur time.Duration, claims T) *BaseTypeClaims[T] {
	now := time.Now()
	return (&BaseTypeClaims[T]{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    p.Issuer(),
			Subject:   sub,
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
func ExtractClaims[T Claims](p Verifier, token string) (*jwt.Token, BaseTypeClaims[T], error) {
	b := BaseTypeClaims[T]{
		RegisteredClaims: jwt.RegisteredClaims{},
		Claims:           *new(T),
	}
	tok, err := p.VerifyJwt(token, &b)
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

type BaseTypeClaims[T Claims] struct {
	jwt.RegisteredClaims
	ClaimType string
	Claims    T
}

func (b *BaseTypeClaims[T]) init() *BaseTypeClaims[T] {
	b.ClaimType = b.InternalClaimType()
	return b
}

func (b *BaseTypeClaims[T]) Valid() error {
	if b.ClaimType != b.InternalClaimType() {
		return ErrClaimTypeMismatch
	}
	return b.Claims.Valid()
}

func (b *BaseTypeClaims[T]) InternalClaimType() string {
	return b.Claims.Type()
}

func (b *BaseTypeClaims[T]) MarshalJSON() ([]byte, error) {
	// setup buffers
	buf := new(bytes.Buffer)
	buf2 := new(bytes.Buffer)

	// encode into both buffers
	err := json.NewEncoder(buf).Encode(internalBaseTypeClaims{
		RegisteredClaims: b.RegisteredClaims,
		ClaimType:        b.InternalClaimType(),
	})
	if err != nil {
		return nil, err
	}
	err = json.NewEncoder(buf2).Encode(b.Claims)
	if err != nil {
		return nil, err
	}

	// decode into a single map
	var a map[string]any
	err = json.NewDecoder(buf).Decode(&a)
	if err != nil {
		return nil, err
	}
	err = json.NewDecoder(buf2).Decode(&a)
	if err != nil {
		return nil, err
	}

	// encode to output
	return json.Marshal(a)
}

func (b *BaseTypeClaims[T]) UnmarshalJSON(bytes []byte) error {
	a := internalBaseTypeClaims{}
	var t T
	err := json.Unmarshal(bytes, &a)
	if err != nil {
		return err
	}
	err = json.Unmarshal(bytes, &t)
	if err != nil {
		return err
	}

	b.RegisteredClaims = a.RegisteredClaims
	b.ClaimType = a.ClaimType
	b.Claims = t
	return err
}

type internalBaseTypeClaims struct {
	jwt.RegisteredClaims
	ClaimType string `json:"mct"`
}
