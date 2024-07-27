package auth

import (
	"github.com/1f349/mjwt"
	"github.com/golang-jwt/jwt/v4"
	"time"
)

// AccessTokenClaims contains the JWT claims for an access token
type AccessTokenClaims struct {
	Perms *PermStorage `json:"per"`
}

func (a AccessTokenClaims) Valid() error { return nil }

func (a AccessTokenClaims) Type() string { return "access-token" }

// CreateAccessToken creates an access token with the default 15 minute duration
func CreateAccessToken(p *mjwt.Issuer, sub, id string, aud jwt.ClaimStrings, perms *PermStorage) (string, error) {
	return CreateAccessTokenWithDuration(p, time.Minute*15, sub, id, aud, perms)
}

// CreateAccessTokenWithDuration creates an access token with a custom duration
func CreateAccessTokenWithDuration(p *mjwt.Issuer, dur time.Duration, sub, id string, aud jwt.ClaimStrings, perms *PermStorage) (string, error) {
	return p.GenerateJwt(sub, id, aud, dur, &AccessTokenClaims{Perms: perms})
}
