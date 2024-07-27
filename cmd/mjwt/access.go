package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/1f349/mjwt"
	"github.com/1f349/mjwt/auth"
	"github.com/1f349/rsa-helper/rsaprivate"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/subcommands"
	"os"
	"strings"
	"time"
)

type accessCmd struct {
	issuer, subject, id, audience, duration, kID string
}

func (s *accessCmd) Name() string { return "access" }
func (s *accessCmd) Synopsis() string {
	return "Generates an access token with permissions using the private key"
}
func (s *accessCmd) Usage() string {
	return `sign [-iss <issuer>] [-sub <subject>] [-id <id>] [-aud <audience>] [-dur <duration>] [-kid <name>] <private key path> <space separated permissions>
  Output a signed MJWT token with the specified permissions.
`
}

func (s *accessCmd) SetFlags(f *flag.FlagSet) {
	f.StringVar(&s.issuer, "iss", "MJWT Utility", "The name of the MJWT issuer (default: MJWT Utility)")
	f.StringVar(&s.subject, "sub", "", "MJWT Subject")
	f.StringVar(&s.id, "id", "", "MJWT ID")
	f.StringVar(&s.audience, "aud", "", "Comma separated audience items for the MJWT")
	f.StringVar(&s.duration, "dur", "15m", "Duration for the MJWT (default: 15m)")
	f.StringVar(&s.kID, "kid", "", "The Key ID of the signing key")
}

func (s *accessCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	if f.NArg() < 1 {
		_, _ = fmt.Fprintln(os.Stderr, "Error: Missing private key path argument")
		return subcommands.ExitFailure
	}

	args := f.Args()
	key, err := rsaprivate.Read(args[0])
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "Error: Failed to parse private key: ", err)
		return subcommands.ExitFailure
	}

	ps := auth.NewPermStorage()
	for i := 1; i < len(args); i++ {
		ps.Set(args[i])
	}

	var aud jwt.ClaimStrings
	if s.audience != "" {
		aud = strings.Split(s.audience, ",")
	}
	dur, err := time.ParseDuration(s.duration)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "Error: Failed to parse duration: ", err)
		return subcommands.ExitFailure
	}

	var token string

	kStore := mjwt.NewKeyStore()
	kStore.LoadPrivateKey(s.kID, key)

	issuer, err := mjwt.NewIssuerWithKeyStore(s.issuer, s.kID, kStore)
	if err != nil {
		panic("this should not fail")
	}

	token, err = issuer.GenerateJwt(s.subject, s.id, aud, dur, auth.AccessTokenClaims{Perms: ps})
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "Error: Failed to generate MJWT token: ", err)
		return subcommands.ExitFailure
	}

	fmt.Println(token)
	return subcommands.ExitSuccess
}
