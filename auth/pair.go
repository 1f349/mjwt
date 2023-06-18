package auth

import (
	"github.com/MrMelon54/mjwt"
	"github.com/MrMelon54/mjwt/claims"
	"time"
)

// CreateTokenPair creates an access and refresh token pair using the default
// 15 minute and 7 day durations respectively
func CreateTokenPair(p mjwt.Signer, sub, id string, userId uint64, perms *claims.PermStorage) (string, string, error) {
	return CreateTokenPairWithDuration(p, time.Minute*15, time.Hour*24*7, sub, id, userId, perms)
}

// CreateTokenPairWithDuration creates an access and refresh token pair using
// custom durations for the access and refresh tokens
func CreateTokenPairWithDuration(p mjwt.Signer, accessDur, refreshDur time.Duration, sub, id string, userId uint64, perms *claims.PermStorage) (string, string, error) {
	accessToken, err := CreateAccessTokenWithDuration(p, accessDur, sub, id, userId, perms)
	if err != nil {
		return "", "", err
	}
	refreshToken, err := CreateRefreshTokenWithDuration(p, refreshDur, sub, id, userId, perms)
	if err != nil {
		return "", "", err
	}
	return accessToken, refreshToken, nil
}
