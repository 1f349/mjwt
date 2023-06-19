package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"github.com/google/subcommands"
	"math/rand"
	"os"
	"time"
)

type genCmd struct {
	bits int
}

func (g *genCmd) Name() string     { return "gen" }
func (g *genCmd) Synopsis() string { return "Generate RSA private key" }
func (g *genCmd) Usage() string {
	return `gen <private key path> <public key path>
  Output RSA private key to the provided file.
`
}

func (g *genCmd) SetFlags(f *flag.FlagSet) {
	f.IntVar(&g.bits, "bits", 4096, "Number of bits to generate (default: 4096)")
}

func (g *genCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	if f.NArg() != 2 {
		_, _ = fmt.Fprintln(os.Stderr, "Error: Missing private and public key file")
		return subcommands.ExitFailure
	}

	// arguments
	privPath := f.Arg(0)
	pubPath := f.Arg(1)

	if err := g.gen(privPath, pubPath); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "An error occured generating the private and public keys: ", err)
		return subcommands.ExitFailure
	}

	fmt.Println("Success generating RSA private key")
	return subcommands.ExitSuccess
}

func (g *genCmd) gen(privPath, pubPath string) error {
	createPriv, err := os.OpenFile(privPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer createPriv.Close()

	createPub, err := os.OpenFile(pubPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer createPub.Close()

	key, err := rsa.GenerateKey(rand.New(rand.NewSource(time.Now().UnixNano())), g.bits)
	if err != nil {
		return err
	}

	keyBytes := x509.MarshalPKCS1PrivateKey(key)
	pubBytes := x509.MarshalPKCS1PublicKey(&key.PublicKey)
	err = pem.Encode(createPriv, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes})
	if err != nil {
		return err
	}
	err = pem.Encode(createPub, &pem.Block{Type: "RSA PUBLIC KEY", Bytes: pubBytes})
	return err
}
