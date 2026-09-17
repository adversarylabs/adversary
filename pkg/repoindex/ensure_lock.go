package repoindex

import "sync"

// Index publication is destructive while it is in progress: builders replace
// the cache directory when they finish. Composite reviews can ask many
// adversaries to index the same checkout concurrently, so serialize builders
// that target the same cache entry while allowing unrelated repositories and
// schema versions to build in parallel.
var ensureLocks sync.Map

func lockEnsure(key string) func() {
	value, _ := ensureLocks.LoadOrStore(key, &sync.Mutex{})
	mu := value.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}
