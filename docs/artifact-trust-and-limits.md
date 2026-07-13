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
are rejected. The config is mandatory, strictly typed, and rejects unknown or
duplicate JSON fields. Its deterministic creation marker, identity, runtime
name/version/image, entrypoint, producer annotations, and complete uniquely
sorted file inventory are cross-checked against both the canonical
`adversary.yaml` and the extracted package layer. Every listed path must exist
exactly once with no unlisted files; sizes, normalized `0644`/`0755` modes, and
SHA-256 hashes must match. Published files
are read-only and every published directory is non-writable; executable intent
is retained as read-and-execute mode. Staging trees are sealed and policy-checked
before atomic publication, then checked again at the destination. Named and
image-based runtime identities and entrypoints are carried and cross-checked.
The package digest, manifest digest, and original reference are retained by the
unified repository record and durable reference index.
SHA-256 remains the producer default, while registered SHA-384 and SHA-512 OCI
digests are preserved and verified for manifests, configs, layers, attached
manifests, inventory reads, repository repair, and materialization.

Publication uses a validated staging directory and an atomic no-follow,
no-replace rename into the canonical digest path. On every platform all children
are sealed first, the private stage root remains `0755` for the rename, and the
destination root is immediately changed to `0555` and validated
while a per-digest interprocess lock excludes cooperating publishers and
resolvers. Cooperating CLI processes therefore see only absent or complete
digest paths; a losing publisher validates the sealed winner. No remote
artifact code runs during this transition. A malicious process running as the same OS user is outside this
boundary because that principal can change permissions on installed content
after publication (the credential-storage decision uses the same same-user
authority boundary). Platforms that cannot rename a sealed directory safely
fail closed instead of making the stage writable.

Repository roots are opened with rooted, no-follow operations and a configured
root that is itself a symlink is rejected. The root pathname is expected to
remain stable for each operation. Defending against a hostile same-UID process
that swaps that configured ancestor is outside the cooperative CLI boundary,
just like post-install permission changes by that same principal.

Repository name and reference aliases have exact-byte interprocess locks and
atomic record replacement, so readers observe one complete record. Reference
updates use compare-and-swap and aliases fail closed when ambiguous.

Canonical `adversary.yaml` is normally an attached OCI referrer and is injected
only when the validated package layer does not already contain it. A legacy
layer-backed copy is accepted only when it is present in the exact config
inventory; it is promoted to durable attached metadata during import. If both
copies exist their bytes must be identical. Missing or conflicting copies fail
before content, record, reference, or materialization publication. Content that
was durably written by a later transaction failure remains untrusted and
unreferenced for normal GC; validation failures occur before those writes.
Import opens each caller-owned source exactly once into a verified private
stage; semantic validation and durable publication reopen only that immutable
stage, preventing a changing source from swapping bytes between validation and
commit.

Stored records are semantically revalidated from the immutable config and a
fresh bounded extraction before inventory display, republishing, or execution.
An older record created before this gate therefore cannot bypass the checks via
an already sealed materialization. For a valid pre-gate record whose only
canonical manifest is inventory-backed in the layer, payload acquisition
synthesizes the verified attached-manifest source without mutating repository
state while the digest lease is held.

Digest verification provides content integrity, not publisher identity. This
change does not introduce signatures because the repository has no configured
publisher trust roots or provenance policy. A future signature feature must
define trust-root enrollment, rotation, revocation, offline behavior, and the
identity bound to a package name before it can safely become an install gate.
Running code obtained from a remote host therefore continues to require the
existing explicit acknowledgement.

Package layers remain file-backed throughout production flows. Registry pulls
stream into an owned temporary source while verifying the declared size and
digest; repository import then streams that source into durable content. Push
and repair paths open repeatable sources, and repository payload leases keep
their records live across retry/reopen lifetimes. Every owner closes its readers
before releasing the source or lease, including cancellation and error paths.
Only bounded control-plane manifests and configs are materialized in memory.

When a registry canonicalizes an uploaded manifest to another supported digest
algorithm, push commits an equivalent local record under the verified
registry-returned digest before registering the explicit remote reference. It
reuses the already verified config, layer, and adversary-manifest sources and
reverifies the identical manifest bytes against the returned digest. The
upload lease is released before this lifecycle-first repository transaction,
preventing GC and opposite-canonicalization lock cycles. The original generic
reference and digest record remain unchanged.

Equivalent records may persist a validated canonical-alias digest as a root
preference, but equivalence is proven independently from the exact verified
manifest bytes and attached adversary-manifest digest. Name and name-version
aliases collapse only when every visible candidate has the same semantic key.
An agreed, present preferred root wins; otherwise independently imported or
GC-surviving equivalents resolve to their lexicographically smallest digest.
A deleted preferred root is not required to create another verified algorithm
identity. Records with different bytes or attached semantics remain ambiguous
and fail closed.

Packaging refuses non-regular inputs (including symlinks), streams hashing and
tar writes, produces deterministic timestamps and ordering, and records the
executable bits. Existing ignore-file matching remains intentionally unchanged;
changing its grammar is a separate compatibility decision.

Rollback is code-only and introduces no record or content-path migration. Valid
existing artifacts remain readable; previously accepted artifacts whose config,
layer, annotations, or canonical manifest conflict now fail closed and must be
repacked. Reverting the
bounded reader/extractor hardening reopens the resource-amplification and
link/type acceptance risks described here, so those checks must remain a
coherent unit. Previously installed digest-addressed artifacts remain usable.
