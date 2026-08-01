package officialsig

// embeddedOfficialV1PublicKey is the Ed25519 public key for key id official-v1
// (hex-encoded, 32 bytes). The matching private seed is held in release CI
// (ADVERSARY_OFFICIAL_SIGNING_SEED) and is not shipped in the CLI.
//
// Rotate by adding official-v2 to DefaultKeyring and retiring this id after
// the catalog is re-signed.
const embeddedOfficialV1PublicKey = "c3c66329356f0b0fdb4f2f7646684376fffd22801006ee4989d3970362b79535"
