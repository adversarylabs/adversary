# Streaming artifact source contract

CLI-019 was resolved through additive, migration, and cleanup pull requests.
`pkg/blobsource.Source` and its pack, repository, and OCI adapters are now the
production package-layer path; the cleanup removed the whole-layer byte-slice
compatibility APIs.

A source has immutable size and digest metadata and returns a new reader at byte
zero for every successful `Open`. The caller owns each reader and must close it.
Retrying a registry request therefore opens a new reader rather than seeking or
retaining a whole blob. `blobsource.Verify` hashes while copying and reports
size, digest, read, and close failures without buffering content.

Plain byte and file sources do not own their backing storage. `Owned` sources
are used for temporary downloads: their owner must call `Close` to run cleanup.
Close prevents new opens; if a reader remains active it returns
`ErrActiveReaders` without releasing the content, so the owner closes its
readers and retries cleanup. This is deterministic on platforms such as Windows
that cannot remove an open file.

`Repository.PayloadSources` returns a cross-process lease, not bare sources.
It acquires locks in lifecycle-then-record order, then retains only the
record-specific lock. The lease prevents garbage collection for the complete
retry/reopen lifetime without blocking unrelated repository operations.
Callers close all readers and then close the lease; an active-reader error keeps
the record-specific lock held for retry. Construction failures release the lock.

Production pack output streams into owned temporary
sources, imports sources into the repository with atomic verified writes, and
uses source-based OCI upload and download paths. Upload authentication retries
reopen a source at byte zero. Downloads verify size and digest while writing an
owned temporary file and remove every partial or accumulated file on failure.
Command paths hold repository payload leases through publication and close
download/pack ownership after import. Bounded manifest, config, and adversary
YAML metadata remain in memory; package layers do not.

The allocation regression writes 64 MiB of deterministic pseudo-random
(incompressible) input before measurement, forces a collection, and requires
the complete streaming pack operation to allocate no more than 8 MiB according
to `runtime.MemStats.TotalAlloc`. The companion benchmark reports allocations
for the same deterministic workload. Source readers are additionally tested to
consume at most their declared size plus the one-byte EOF probe.

The cleanup removed legacy whole-blob fields and compatibility methods.
Rolling back the migration restores the former command adapters; stored
repository records and content paths remain format-compatible.
