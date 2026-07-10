# Artifact trust and ingestion limits

This decision resolves CLI-005, CLI-019, and CLI-020 for the current artifact
format.

Adversary accepts only OCI schema 2 manifests whose artifact type is the
Adversary artifact media type, with exactly one Adversary config and exactly one
gzip package layer. Container images and generic OCI layers are rejected.
Manifests are limited to 4 MiB, configs and attached `adversary.yaml` documents
to 1 MiB, and compressed package layers to 256 MiB.

Extraction first spools the complete compressed input into a private temporary
file through a hard limit, so unread or trailing bytes cannot evade accounting.
Defaults are configurable through `archiveutil.Limits`: 256 MiB
compressed, 1 GiB expanded, 256 MiB per file, 10,000 entries, 4,096 bytes per
path, and a 100:1 expansion ratio. Extraction streams into a private staging
directory and accepts regular files and directories only. Links, devices,
sparse entries, duplicate paths, traversal, and paths outside that directory
are rejected. The config is mandatory and its identity, runtime, annotations,
complete file set, sizes, modes, and hashes are cross-checked. Published files
are read-only and every published directory is non-writable; executable intent
is retained as read-and-execute mode. The package digest, manifest digest, and original
reference are retained by the existing cache record.

Digest verification provides content integrity, not publisher identity. This
change does not introduce signatures because the repository has no configured
publisher trust roots or provenance policy. A future signature feature must
define trust-root enrollment, rotation, revocation, offline behavior, and the
identity bound to a package name before it can safely become an install gate.
Running code obtained from a remote host therefore continues to require the
existing explicit acknowledgement.

The registry API still returns blobs as byte slices after a bounded streaming
read because `PulledArtifact` and the store interfaces are byte-slice based.
Moving the private temporary blob through the resolver and store without this
final materialization is deferred to the unified resolver API migration; the
bounds above apply at the network and extraction boundaries meanwhile.

Packaging refuses non-regular inputs (including symlinks), streams hashing and
tar writes, produces deterministic timestamps and ordering, and records the
executable bits. Existing ignore-file matching remains intentionally unchanged;
changing its grammar is a separate compatibility decision.

Rollback is code-only: revert the bounded reader/extractor commit. Previously
installed digest-addressed artifacts remain usable, but reverting reopens the
resource-amplification and link/type acceptance risks described here.
