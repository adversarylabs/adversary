# Streaming artifact source contract

CLI-019 is being resolved as an additive, migration, and cleanup sequence. This
additive change introduces `pkg/blobsource.Source` and adapters in pack,
repository, and OCI code. Existing byte-slice APIs remain the production path
until the migration PR.

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

The migration PR will stream pack output into owned temporary sources, import
sources into the repository with atomic verified writes, and teach OCI upload
and download paths to consume and produce sources. A final cleanup PR will
remove the legacy whole-blob fields after all callers migrate. Rolling back this
additive PR removes only the new types, adapters, tests, and this document;
stored artifacts and existing APIs are unchanged.
