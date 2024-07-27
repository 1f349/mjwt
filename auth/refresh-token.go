package auth

import (
	"github.com/1f349/mjwt"
	"github.com/golang-jwt/jwt/v4"
	"time"
)

// RefreshTokenClaims contains the JWT claims for a refresh token
// AccessTokenId (ati) must match the similar JWT ID (jti) claim
type RefreshTokenClaims struct {
	AccessTokenId string `json:"ati"`
}

func (r RefreshTokenClaims) Valid() error { return nil }
func (r RefreshTokenClaims) Type() string { return "refresh-token" }

// CreateRefreshToken creates a refresh token with the default 7 day duration
func CreateRefreshToken(p *mjwt.Issuer, sub, id, ati string, aud jwt.ClaimStrings) (string, error) {
	return CreateRefreshTokenWithDuration(p, time.Hour*24*7, sub, id, ati, aud)
}

// CreateRefreshTokenWithDuration creates a refresh token with a custom duration
func CreateRefreshTokenWithDuration(p *mjwt.Issuer, dur time.Duration, sub, id, ati string, aud jwt.ClaimStrings) (string, error) {
	return p.GenerateJwt(sub, id, aud, dur, RefreshTokenClaims{AccessTokenId: ati})
}
