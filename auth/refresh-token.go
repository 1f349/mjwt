package auth

import (
	"github.com/MrMelon54/mjwt"
	"github.com/MrMelon54/mjwt/claims"
	"time"
)

// RefreshTokenClaims contains the JWT claims for a refresh token
type RefreshTokenClaims struct {
	UserId uint64              `json:"uid"`
	Perms  *claims.PermStorage `json:"per"`
}

func (r RefreshTokenClaims) Valid() error { return nil }
func (r RefreshTokenClaims) Type() string { return "refresh-token" }

// CreateRefreshToken creates a refresh token with the default 7 day duration
func CreateRefreshToken(p mjwt.Signer, sub, id string, userId uint64, perms *claims.PermStorage) (string, error) {
	return CreateRefreshTokenWithDuration(p, time.Hour*24*7, sub, id, userId, perms)
}

// CreateRefreshTokenWithDuration creates a refresh token with a custom duration
func CreateRefreshTokenWithDuration(p mjwt.Signer, dur time.Duration, sub, id string, userId uint64, perms *claims.PermStorage) (string, error) {
	return p.GenerateJwt(sub, id, dur, RefreshTokenClaims{
		UserId: userId,
		Perms:  perms,
	})
}
