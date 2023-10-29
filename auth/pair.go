package auth

import (
	"github.com/1f349/mjwt"
	"github.com/1f349/mjwt/claims"
	"github.com/golang-jwt/jwt/v4"
	"time"
)

// CreateTokenPair creates an access and refresh token pair using the default
// 15 minute and 7 day durations respectively
func CreateTokenPair(p mjwt.Signer, sub, id, rId string, aud, rAud jwt.ClaimStrings, perms *claims.PermStorage) (string, string, error) {
	return CreateTokenPairWithDuration(p, time.Minute*15, time.Hour*24*7, sub, id, rId, aud, rAud, perms)
}

// CreateTokenPairWithDuration creates an access and refresh token pair using
// custom durations for the access and refresh tokens
func CreateTokenPairWithDuration(p mjwt.Signer, accessDur, refreshDur time.Duration, sub, id, rId string, aud, rAud jwt.ClaimStrings, perms *claims.PermStorage) (string, string, error) {
	accessToken, err := CreateAccessTokenWithDuration(p, accessDur, sub, id, aud, perms)
	if err != nil {
		return "", "", err
	}
	refreshToken, err := CreateRefreshTokenWithDuration(p, refreshDur, sub, rId, id, rAud)
	if err != nil {
		return "", "", err
	}
	return accessToken, refreshToken, nil
}
