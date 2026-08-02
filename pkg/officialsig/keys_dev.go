//go:build !release

package officialsig

// DefaultKeyID is the key id expected for signatures this binary accepts.
// Dev/default builds trust only the development official key so local catalog
// work does not depend on the production signing secret.
const DefaultKeyID = DevKeyID

// embeddedOfficialPublicKey is the development Ed25519 public key (hex, 32 bytes).
// Matching seed: local/dev secret ADVERSARY_OFFICIAL_SIGNING_SEED (dev only). Never commit the seed.
const embeddedOfficialPublicKey = "9627a459b53a07cf675515dd747b8fa6464d031aaf77ee60afed5b13b443f4de"

func buildKeyring() Keyring {
	return Keyring{DevKeyID: mustParsePublicKey(embeddedOfficialPublicKey)}
}
