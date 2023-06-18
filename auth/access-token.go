package auth

import (
	"github.com/MrMelon54/mjwt"
	"github.com/MrMelon54/mjwt/claims"
	"time"
)

// AccessTokenClaims contains the JWT claims for an access token
type AccessTokenClaims struct {
	UserId uint64              `json:"uid"`
	Perms  *claims.PermStorage `json:"per"`
}

func (a AccessTokenClaims) Valid() error { return nil }

func (a AccessTokenClaims) Type() string { return "access-token" }

// CreateAccessToken creates an access token with the default 15 minute duration
func CreateAccessToken(p mjwt.Signer, sub, id string, userId uint64, perms *claims.PermStorage) (string, error) {
	return CreateAccessTokenWithDuration(p, time.Minute*15, sub, id, userId, perms)
}

// CreateAccessTokenWithDuration creates an access token with a custom duration
func CreateAccessTokenWithDuration(p mjwt.Signer, dur time.Duration, sub, id string, userId uint64, perms *claims.PermStorage) (string, error) {
	return p.GenerateJwt(sub, id, dur, &AccessTokenClaims{
		UserId: userId,
		Perms:  perms,
	})
}
