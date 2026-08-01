// Command sign-official creates an official catalog signature envelope for an
// artifact digest. Intended for release CI (not required on end-user machines).
//
// Usage:
//
//	export ADVERSARY_OFFICIAL_SIGNING_SEED=<64 hex chars>
//	go run ./scripts/sign-official -digest sha256:... -out signature.json
//
// Then attach with the registry tool or:
//
//	notation-style push is not required; use adversary's PushOfficialSignatureReferrer
//	or oras/curl against the registry API.
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/adversarylabs/adversary/pkg/officialsig"
)

func main() {
	digest := flag.String("digest", "", "subject artifact digest (sha256:...)")
	keyID := flag.String("key-id", officialsig.DefaultKeyID, "official key id")
	out := flag.String("out", "", "write envelope JSON to this path (default stdout)")
	flag.Parse()
	if *digest == "" {
		fmt.Fprintln(os.Stderr, "usage: sign-official -digest sha256:... [-out signature.json]")
		os.Exit(2)
	}
	seed := os.Getenv("ADVERSARY_OFFICIAL_SIGNING_SEED")
	if seed == "" {
		fmt.Fprintln(os.Stderr, "ADVERSARY_OFFICIAL_SIGNING_SEED is required (hex seed or private key)")
		os.Exit(2)
	}
	priv, err := officialsig.ParsePrivateKeySeed(seed)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	env, err := officialsig.Sign(*digest, *keyID, priv, time.Now().UTC())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	raw, err := officialsig.MarshalEnvelope(env)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if *out == "" {
		_, _ = os.Stdout.Write(append(raw, '\n'))
		return
	}
	if err := os.WriteFile(*out, raw, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
