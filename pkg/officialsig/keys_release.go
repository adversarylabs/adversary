//go:build release

package officialsig

// DefaultKeyID is the key id expected for signatures this binary accepts.
const DefaultKeyID = ProdKeyID

// embeddedOfficialPublicKey is the production Ed25519 public key (hex, 32 bytes).
// Matching seed: CI secret ADVERSARY_OFFICIAL_SIGNING_SEED (prod only). Never commit the seed.
const embeddedOfficialPublicKey = "aa677c95b60ecf3642db92a8c2e79a153834787e29b5fa16197e39e6c7b8534c"

func buildKeyring() Keyring {
	return Keyring{ProdKeyID: mustParsePublicKey(embeddedOfficialPublicKey)}
}
