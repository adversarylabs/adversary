//go:build release

package officialsig

// DefaultKeyID is the key id expected for signatures this binary accepts.
const DefaultKeyID = ProdKeyID

// embeddedOfficialPublicKey is the production Ed25519 public key (hex, 32 bytes).
// Matching seed: CI secret ADVERSARY_OFFICIAL_SIGNING_SEED (prod only). Never commit the seed.
const embeddedOfficialPublicKey = "ff042866af7c77b63d03e8f8845b01191e63d90c9267369cc55a616e95a9e4d0"

func buildKeyring() Keyring {
	return Keyring{ProdKeyID: mustParsePublicKey(embeddedOfficialPublicKey)}
}
