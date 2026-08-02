//go:build !release

package officialsig

// DefaultKeyID is the key id expected for signatures this binary accepts.
// Dev/default builds trust only the development official key so local catalog
// work does not depend on the production signing secret.
const DefaultKeyID = DevKeyID

// embeddedOfficialPublicKey is the development Ed25519 public key (hex, 32 bytes).
// Matching seed: local/dev secret ADVERSARY_OFFICIAL_SIGNING_SEED (dev only). Never commit the seed.
const embeddedOfficialPublicKey = "8b91b3823dab66e0d48622363ae63d4ce51b791f76aa77191b317b97254b2d16"

func buildKeyring() Keyring {
	return Keyring{DevKeyID: mustParsePublicKey(embeddedOfficialPublicKey)}
}
