package adversary

import (
	"fmt"
	"strings"

	"github.com/adversarylabs/adversary/pkg/oci"
	"github.com/adversarylabs/adversary/pkg/repository"
)

type PublisherTrust string

const (
	LocalSourceTrust      PublisherTrust = "local-source"
	TrustedPublisherTrust PublisherTrust = "trusted-publisher"
	UnknownPublisherTrust PublisherTrust = "unknown-publisher"
)

type PublisherIdentity struct {
	Name      string
	Registry  string
	Reference string
	Local     bool
	// OfficialSigned is true when a valid official catalog signature was verified
	// for this artifact digest (see pkg/officialsig).
	OfficialSigned bool
	// NamespaceSigned is true when a platform-delegated team signature verifies
	// for this digest and exact registry repository.
	NamespaceSigned bool
	Digest          string
}

func classifyPublisher(input string, resolved ResolvedAdversary, explicitLocal bool) (PublisherIdentity, error) {
	if explicitLocal && !resolved.StoreBacked {
		return PublisherIdentity{Name: "local", Reference: input, Local: true}, nil
	}
	if !resolved.StoreBacked {
		return PublisherIdentity{Name: "unknown", Reference: input}, nil
	}
	reference := resolved.CanonicalReference
	if _, err := oci.ParseDigest(reference); err == nil {
		return PublisherIdentity{Name: "unknown", Reference: reference}, nil
	}
	parsed, err := oci.ParseReference(reference)
	if err != nil {
		return PublisherIdentity{}, fmt.Errorf("classify publisher for %q: %w", reference, err)
	}
	publisher, _, _ := strings.Cut(parsed.Repository, "/")
	if publisher == "" {
		publisher = "unknown"
	}
	id := PublisherIdentity{
		Name:      publisher,
		Registry:  parsed.Registry,
		Reference: reference,
		Digest:    resolved.Digest,
	}
	if id.Digest == "" {
		id.Digest = resolved.StoreRecord.Digest
	}
	return id, nil
}

// withArtifactSignature records any verified official or hosted namespace
// signature for the artifact digest and source repository.
func withArtifactSignature(id PublisherIdentity, repo *repository.Repository) PublisherIdentity {
	if id.Local || repo == nil {
		return id
	}
	digest := id.Digest
	if digest == "" {
		return id
	}
	id.OfficialSigned = repo.HasVerifiedOfficialSignature(digest)
	if parsed, err := oci.ParseReference(id.Reference); err == nil {
		id.NamespaceSigned = repo.HasVerifiedNamespaceSignature(digest, parsed.Registry, parsed.Repository)
	}
	return id
}

type PermissionRequirements struct {
	Requested RequestedPermissions
	Required  RequestedPermissions
}

func permissionRequirements(resolved ResolvedAdversary, opts RunOptions) PermissionRequirements {
	requirements := PermissionRequirements{}
	if opts.NoNetwork {
		requirements.Requested.NetworkIsolation = true
		requirements.Required.NetworkIsolation = true
	}
	if resolved.Manifest == nil {
		return requirements
	}
	permissions := resolved.Manifest.Permissions
	requirements.Requested.FilesystemReadIsolation = len(permissions.Filesystem.Read) > 0
	requirements.Requested.FilesystemWriteIsolation = len(permissions.Filesystem.Write) > 0
	requirements.Requested.EnvironmentIsolation = len(permissions.Environment.Allow) > 0
	requirements.Requested.NetworkIsolation = requirements.Requested.NetworkIsolation || resolved.NetworkOff
	requirements.Requested.ModelAccess = permissions.Model
	if permissions.Enforcement == "required" {
		requirements.Required = requirements.Requested
	}
	return requirements
}

type TrustDecision struct {
	Publisher PublisherIdentity
	Trust     PublisherTrust
}

// PublisherTrustPolicy is deliberately replaceable so signatures, verified
// publishers, and enterprise trust stores can replace the built-in policy.
type PublisherTrustPolicy interface {
	Evaluate(PublisherIdentity) TrustDecision
}

// StaticPublisherTrustPolicy trusts an explicit set of publisher path segments.
// Prefer OfficialSignatureTrustPolicy for production; this remains for tests
// and embedders that inject a fixed allowlist.
type StaticPublisherTrustPolicy struct {
	Trusted map[string]struct{}
}

func (p StaticPublisherTrustPolicy) Evaluate(publisher PublisherIdentity) TrustDecision {
	if publisher.Local {
		return TrustDecision{Publisher: publisher, Trust: LocalSourceTrust}
	}
	if _, trusted := p.Trusted[strings.ToLower(publisher.Name)]; trusted {
		return TrustDecision{Publisher: publisher, Trust: TrustedPublisherTrust}
	}
	return TrustDecision{Publisher: publisher, Trust: UnknownPublisherTrust}
}

// OfficialSignatureTrustPolicy trusts packages with a verified official or
// hosted namespace signature and local source projects. Path allowlists and a
// registry hostname by itself are never sufficient.
type OfficialSignatureTrustPolicy struct{}

// DefaultPublisherTrustPolicy returns the production trust policy based on
// cryptographic signatures verified by the CLI.
func DefaultPublisherTrustPolicy() PublisherTrustPolicy {
	return OfficialSignatureTrustPolicy{}
}

func (OfficialSignatureTrustPolicy) Evaluate(publisher PublisherIdentity) TrustDecision {
	if publisher.Local {
		return TrustDecision{Publisher: publisher, Trust: LocalSourceTrust}
	}
	if publisher.OfficialSigned || publisher.NamespaceSigned {
		return TrustDecision{Publisher: publisher, Trust: TrustedPublisherTrust}
	}
	return TrustDecision{Publisher: publisher, Trust: UnknownPublisherTrust}
}

type RequestedPermissions struct {
	FilesystemReadIsolation  bool
	FilesystemWriteIsolation bool
	EnvironmentIsolation     bool
	NetworkIsolation         bool
	CPULimits                bool
	MemoryLimits             bool
	ProcessLimits            bool
	ModelAccess              bool
}

type AllowedPermissions struct {
	FilesystemReadIsolation  bool
	FilesystemWriteIsolation bool
	EnvironmentIsolation     bool
	NetworkIsolation         bool
	CPULimits                bool
	MemoryLimits             bool
	ProcessLimits            bool
	ModelAccess              bool
}

type PermissionPolicy interface {
	Allowed(TrustDecision) AllowedPermissions
}

type AllowRequestedPermissionsPolicy struct{}

func (AllowRequestedPermissionsPolicy) Allowed(TrustDecision) AllowedPermissions {
	return AllowedPermissions{
		FilesystemReadIsolation:  true,
		FilesystemWriteIsolation: true,
		EnvironmentIsolation:     true,
		NetworkIsolation:         true,
		CPULimits:                true,
		MemoryLimits:             true,
		ProcessLimits:            true,
		ModelAccess:              true,
	}
}

type ExecutionPolicyRequest struct {
	Trust                    TrustDecision
	Requested                RequestedPermissions
	Required                 RequestedPermissions
	Allowed                  AllowedPermissions
	Backend                  ExecutorBackend
	Capabilities             ExecutorCapabilities
	AllowUnsafeHostExecution bool
}

type ExecutionPolicyDecision struct {
	Allowed        bool
	UnsafeOverride bool
	Reason         string
}

func DecideExecutionPolicy(request ExecutionPolicyRequest) (ExecutionPolicyDecision, error) {
	switch request.Trust.Trust {
	case LocalSourceTrust, TrustedPublisherTrust, UnknownPublisherTrust:
	default:
		return ExecutionPolicyDecision{}, fmt.Errorf("publisher trust policy returned unsupported decision %q", request.Trust.Trust)
	}
	switch request.Backend {
	case HostExecutorBackend, NativeSandboxExecutorBackend, ContainerExecutorBackend:
	default:
		return ExecutionPolicyDecision{}, fmt.Errorf("executor returned unsupported backend %q", request.Backend)
	}
	if err := validateAllowedPermissions(request.Requested, request.Allowed); err != nil {
		return ExecutionPolicyDecision{}, err
	}
	if err := validateExecutorCapabilities(request.Required, request.Capabilities, request.Backend); err != nil {
		return ExecutionPolicyDecision{}, err
	}
	if request.Trust.Trust == UnknownPublisherTrust && request.Backend == HostExecutorBackend {
		if !request.AllowUnsafeHostExecution {
			name := strings.TrimSpace(request.Trust.Publisher.Name)
			if name == "" {
				name = strings.TrimSpace(request.Trust.Publisher.Reference)
			}
			if name == "" {
				name = "adversary"
			}
			return ExecutionPolicyDecision{}, fmt.Errorf(
				"untrusted adversary %q: no valid artifact signature\n\nHost execution of untrusted adversaries is blocked. Re-run with --allow-unsafe-host-execution to allow an unrestricted host process, or use a sandbox executor",
				name,
			)
		}
		return ExecutionPolicyDecision{Allowed: true, UnsafeOverride: true, Reason: "explicit unsafe host execution override"}, nil
	}
	return ExecutionPolicyDecision{Allowed: true}, nil
}

func validateAllowedPermissions(requested RequestedPermissions, allowed AllowedPermissions) error {
	for _, boundary := range []struct {
		requested bool
		allowed   bool
		name      string
	}{
		{requested.FilesystemReadIsolation, allowed.FilesystemReadIsolation, "filesystem.read isolation"},
		{requested.FilesystemWriteIsolation, allowed.FilesystemWriteIsolation, "filesystem.write isolation"},
		{requested.EnvironmentIsolation, allowed.EnvironmentIsolation, "environment.allow isolation"},
		{requested.NetworkIsolation, allowed.NetworkIsolation, "network.none isolation"},
		{requested.CPULimits, allowed.CPULimits, "CPU limits"},
		{requested.MemoryLimits, allowed.MemoryLimits, "memory limits"},
		{requested.ProcessLimits, allowed.ProcessLimits, "process limits"},
		{requested.ModelAccess, allowed.ModelAccess, "model access"},
	} {
		if boundary.requested && !boundary.allowed {
			return fmt.Errorf("execution policy does not allow requested %s", boundary.name)
		}
	}
	return nil
}

func validateExecutorCapabilities(requested RequestedPermissions, supported ExecutorCapabilities, backend ExecutorBackend) error {
	for _, boundary := range []struct {
		requested bool
		supported bool
		name      string
	}{
		{requested.FilesystemReadIsolation, supported.FilesystemReadIsolation, "filesystem.read isolation"},
		{requested.FilesystemWriteIsolation, supported.FilesystemWriteIsolation, "filesystem.write isolation"},
		{requested.EnvironmentIsolation, supported.EnvironmentIsolation, "environment.allow isolation"},
		{requested.NetworkIsolation, supported.NetworkIsolation, "network.none isolation"},
		{requested.CPULimits, supported.CPULimits, "CPU limits"},
		{requested.MemoryLimits, supported.MemoryLimits, "memory limits"},
		{requested.ProcessLimits, supported.ProcessLimits, "process limits"},
	} {
		if boundary.requested && !boundary.supported {
			return fmt.Errorf("%s cannot enforce requested %s", backendDisplayName(backend), boundary.name)
		}
	}
	return nil
}

func backendDisplayName(backend ExecutorBackend) string {
	switch backend {
	case HostExecutorBackend:
		return "HostExecutor"
	case NativeSandboxExecutorBackend:
		return "NativeSandboxExecutor"
	case ContainerExecutorBackend:
		return "ContainerExecutor"
	default:
		return "Executor(" + string(backend) + ")"
	}
}
