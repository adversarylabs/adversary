package officialsig

// embeddedOfficialV1PublicKey is the Ed25519 public key for key id official-v1
// (hex-encoded, 32 bytes). The matching private seed must live only in release
// CI secrets (ADVERSARY_OFFICIAL_SIGNING_SEED) and is never committed.
//
// Rotate by adding official-v2 to the production keyring and retiring this id
// after the catalog is re-signed.
const embeddedOfficialV1PublicKey = "c4c6dc1d98342962a9bd806c18746a241da5c45d74794827becea4e8ce185c80"
