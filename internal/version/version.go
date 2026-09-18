package version

// These values are overridden by release builds with -ldflags -X. Keeping
// deterministic development defaults makes `doomer version` useful in
// source builds as well.
var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)
