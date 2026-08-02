package officialsig

// Key identifiers for official catalog signatures.
//
// Private seeds never live in this package. Public keys are selected at
// compile time (see keys_release.go vs keys_dev.go) so a released CLI binary
// cannot contain the development public key.
const (
	// ProdKeyID is used when signing/verifying production catalog packages.
	ProdKeyID = "official-prod"
	// DevKeyID is used when signing/verifying local/staging catalog packages.
	DevKeyID = "official-dev"
)
