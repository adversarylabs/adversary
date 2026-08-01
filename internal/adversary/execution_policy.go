package adversary

import (
	"fmt"
	"strings"

	"github.com/adversarylabs/adversary/pkg/oci"
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
	return PublisherIdentity{Name: publisher, Registry: parsed.Registry, Reference: reference}, nil
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

type StaticPublisherTrustPolicy struct {
	Trusted map[string]struct{}
}

// Official free-catalog domains (domain/name taxonomy) plus the legacy
// adversarylabs publisher namespace. Host execution is allowed for these first
// path segments without --allow-unsafe-host-execution, including when the
// package was pulled from a local/dev registry (localhost:8787/ci/depot).
//
// Trust is based on catalog path identity, not registry hostname: any host can
// publish under ci/…, so this is a product convenience for official catalog
// packages and local catalog development, not cryptographic publisher auth.
func DefaultPublisherTrustPolicy() StaticPublisherTrustPolicy {
	return StaticPublisherTrustPolicy{Trusted: officialCatalogPublishers()}
}

func officialCatalogPublishers() map[string]struct{} {
	return map[string]struct{}{
		"adversarylabs": {}, // legacy publisher namespace
		"go":            {},
		"ci":            {},
		"container":     {},
		"security":      {},
		"review":        {},
		"infra":         {},
		"deps":          {},
		"meta":          {},
		"cloud":         {},
		"lang":          {},
	}
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
			return ExecutionPolicyDecision{}, fmt.Errorf("unknown publisher %q cannot execute with HostExecutor; select a sandbox or pass --allow-unsafe-host-execution", request.Trust.Publisher.Name)
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
