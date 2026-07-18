//go:build ignore

// verify-ci-contract validates the dependency and privilege structure that
// makes the aggregate CI result and split publication jobs authoritative.
package main

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

var actionRef = regexp.MustCompile(`^[^@[:space:]]+@[0-9a-f]{40}$`)
var setupGoRef = regexp.MustCompile(`^actions/setup-go@[0-9a-f]{40}$`)

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "CI contract: "+format+"\n", args...)
	os.Exit(1)
}

func parse(path string) *yaml.Node {
	data, err := os.ReadFile(path)
	if err != nil {
		fail("read %s: %v", path, err)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		fail("parse %s: %v", path, err)
	}
	if len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		fail("%s must contain one workflow mapping", path)
	}
	return doc.Content[0]
}

func value(node *yaml.Node, key string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1]
		}
	}
	return nil
}

func requiredValue(node *yaml.Node, path ...string) *yaml.Node {
	cur := node
	for _, part := range path {
		cur = value(cur, part)
		if cur == nil {
			fail("missing workflow key %s", strings.Join(path, "."))
		}
	}
	return cur
}

func scalar(node *yaml.Node) string {
	if node == nil || node.Kind != yaml.ScalarNode {
		return ""
	}
	return node.Value
}

func stringSet(node *yaml.Node) map[string]bool {
	result := map[string]bool{}
	if node == nil {
		return result
	}
	switch node.Kind {
	case yaml.ScalarNode:
		result[node.Value] = true
	case yaml.SequenceNode:
		for _, child := range node.Content {
			if child.Kind == yaml.ScalarNode {
				result[child.Value] = true
			}
		}
	}
	return result
}

func requireExactSet(node *yaml.Node, label string, want ...string) {
	got := stringSet(node)
	wanted := map[string]bool{}
	for _, item := range want {
		wanted[item] = true
	}
	if len(got) != len(wanted) {
		fail("%s = %v; want %v", label, sortedKeys(got), sortedKeys(wanted))
	}
	for item := range wanted {
		if !got[item] {
			fail("%s is missing %q", label, item)
		}
	}
}

func sortedKeys(items map[string]bool) []string {
	keys := make([]string, 0, len(items))
	for key := range items {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func steps(job *yaml.Node) []*yaml.Node {
	node := requiredValue(job, "steps")
	if node.Kind != yaml.SequenceNode {
		fail("job steps must be a sequence")
	}
	return node.Content
}

func stepName(step *yaml.Node) string { return scalar(value(step, "name")) }

func findStep(job *yaml.Node, name string) *yaml.Node {
	for _, step := range steps(job) {
		if stepName(step) == name {
			return step
		}
	}
	fail("missing step %q", name)
	return nil
}

func nodeContains(node *yaml.Node, text string) bool {
	if node == nil {
		return false
	}
	if strings.Contains(node.Value, text) {
		return true
	}
	for _, child := range node.Content {
		if nodeContains(child, text) {
			return true
		}
	}
	return false
}

func requirePermissions(node *yaml.Node, label string, want map[string]string) {
	permissions := requiredValue(node, "permissions")
	if permissions.Kind != yaml.MappingNode || len(permissions.Content)/2 != len(want) {
		fail("%s permissions must be exactly %v", label, want)
	}
	for key, expected := range want {
		if got := scalar(value(permissions, key)); got != expected {
			fail("%s permission %s = %q; want %q", label, key, got, expected)
		}
	}
}

func validatePinnedActions(path string, workflow *yaml.Node) {
	jobs := requiredValue(workflow, "jobs")
	if jobs.Kind != yaml.MappingNode {
		fail("%s jobs must be a mapping", path)
	}
	for i := 0; i+1 < len(jobs.Content); i += 2 {
		jobID, job := jobs.Content[i].Value, jobs.Content[i+1]
		for _, step := range steps(job) {
			uses := scalar(value(step, "uses"))
			if uses == "" {
				continue
			}
			if !actionRef.MatchString(uses) {
				fail("%s job %s uses an action that is not pinned to a full commit: %s", path, jobID, uses)
			}
			if strings.HasPrefix(uses, "actions/checkout@") {
				with := value(step, "with")
				if scalar(value(with, "persist-credentials")) != "false" {
					fail("%s job %s checkout must set persist-credentials: false", path, jobID)
				}
			}
		}
	}
}

func requireGoToolchain(job *yaml.Node, jobID string) {
	setupCount := 0
	for _, step := range steps(job) {
		uses := scalar(value(step, "uses"))
		if !strings.HasPrefix(uses, "actions/setup-go@") {
			continue
		}
		setupCount++
		if !setupGoRef.MatchString(uses) {
			fail("job %s setup-go action is not pinned to a full checksum: %s", jobID, uses)
		}
		with := value(step, "with")
		if got := scalar(value(with, "go-version-file")); got != "go.mod" {
			fail("job %s setup-go go-version-file = %q; want go.mod", jobID, got)
		}
		if got := scalar(value(with, "go-version")); got != "" {
			fail("job %s must not override the go.mod toolchain with go-version %q", jobID, got)
		}
	}
	if setupCount != 1 {
		fail("job %s must use exactly one checksum-pinned actions/setup-go step; found %d", jobID, setupCount)
	}
}

func validateCI(workflow *yaml.Node) {
	requirePermissions(workflow, "ci workflow", map[string]string{"contents": "read"})
	concurrency := requiredValue(workflow, "concurrency")
	if scalar(value(concurrency, "cancel-in-progress")) != "true" || scalar(value(concurrency, "group")) == "" {
		fail("ci workflow requires a keyed, cancel-in-progress concurrency policy")
	}

	jobs := requiredValue(workflow, "jobs")
	goJobs := []string{"native-test", "quality", "race", "coverage", "cross-build", "template", "smoke", "tooling", "release-contract"}
	requiredJobs := append(append([]string{}, goJobs...), "test")
	allowedJobs := make(map[string]bool, len(requiredJobs))
	for _, id := range requiredJobs {
		allowedJobs[id] = true
		if value(jobs, id) == nil {
			fail("ci workflow is missing required job %q", id)
		}
	}
	for i := 0; i+1 < len(jobs.Content); i += 2 {
		if id := jobs.Content[i].Value; !allowedJobs[id] {
			fail("ci workflow contains unreviewed job %q; classify it explicitly as a Go job or aggregate", id)
		}
	}
	for _, id := range goJobs {
		requireGoToolchain(requiredValue(jobs, id), "ci "+id)
	}

	native := requiredValue(jobs, "native-test")
	requireExactSet(requiredValue(native, "strategy", "matrix", "os"), "native-test OS matrix", "ubuntu-24.04", "macos-14", "windows-2022")
	if !nodeContains(findStep(native, "Run native contract tests"), "scripts/ci-verify.sh native") {
		fail("native-test does not run the shared native verification stage")
	}

	stages := map[string]string{
		"quality":          "quality",
		"race":             "race",
		"coverage":         "coverage",
		"template":         "template",
		"smoke":            "smoke",
		"tooling":          "tooling",
		"release-contract": "release",
	}
	for jobID, stage := range stages {
		if !nodeContains(requiredValue(jobs, jobID), "scripts/ci-verify.sh "+stage) {
			fail("job %s does not run shared stage %s", jobID, stage)
		}
	}
	for _, jobID := range []string{"native-test", "race", "coverage", "template"} {
		nodeStep := findStep(requiredValue(jobs, jobID), "Set up Node.js")
		if scalar(value(value(nodeStep, "with"), "node-version")) != "22" {
			fail("job %s must install the canonical Node.js 22 runtime", jobID)
		}
	}
	cross := requiredValue(jobs, "cross-build")
	requireExactSet(requiredValue(cross, "strategy", "matrix", "target"), "cross-build target matrix", "linux/amd64", "linux/arm64", "darwin/amd64", "darwin/arm64", "windows/amd64")
	if !nodeContains(cross, "scripts/ci-verify.sh cross") {
		fail("cross-build does not run the shared cross stage")
	}

	aggregate := requiredValue(jobs, "test")
	if scalar(value(aggregate, "name")) != "test" || !strings.Contains(scalar(value(aggregate, "if")), "always()") {
		fail("aggregate job must retain the required check name test and run with always()")
	}
	requireExactSet(value(aggregate, "needs"), "aggregate test dependencies", requiredJobs[:len(requiredJobs)-1]...)
	if !nodeContains(aggregate, "success") {
		fail("aggregate test job does not reject failed dependencies")
	}
}

func requireJobEnvironment(job *yaml.Node, id string) {
	if scalar(value(job, "environment")) != "release" {
		fail("release job %s must use the protected release environment", id)
	}
}

func validateSecretBoundary(job *yaml.Node, jobID, secret, finalStep string) {
	allSteps := steps(job)
	secretStep := -1
	verified := false
	for index, step := range allSteps {
		name := stepName(step)
		if nodeContains(step, "RELEASE_MODE") && nodeContains(step, "verify") {
			verified = true
		}
		if nodeContains(step, "secrets.") {
			if secretStep >= 0 {
				fail("release job %s exposes secrets to more than one step", jobID)
			}
			secretStep = index
			if name != finalStep || !nodeContains(step, secret) {
				fail("release job %s exposes the wrong secret or step", jobID)
			}
			if !verified {
				fail("release job %s exposes its secret before exact bundle verification", jobID)
			}
		}
	}
	if secretStep != len(allSteps)-1 {
		fail("release job %s must expose its channel secret only in the final step", jobID)
	}
}

func validateTokenReferenceBoundary(job *yaml.Node, jobID, token, finalStep string) {
	allSteps := steps(job)
	verified := false
	found := false
	for index, step := range allSteps {
		if nodeContains(step, "RELEASE_MODE") && nodeContains(step, "verify") {
			verified = true
		}
		if !nodeContains(step, token) {
			continue
		}
		if found || index != len(allSteps)-1 || stepName(step) != finalStep || !verified {
			fail("release job %s must reference %s only in its final post-verification step", jobID, token)
		}
		found = true
	}
	if !found {
		fail("release job %s does not reference required token %s", jobID, token)
	}
}

func validatePublicationOrder(job *yaml.Node, jobID, finalStep string) {
	tagIndex, bundleIndex, publishIndex := -1, -1, -1
	for index, step := range steps(job) {
		switch {
		case nodeContains(step, "scripts/verify-release-ref.sh"):
			tagIndex = index
		case nodeContains(step, "RELEASE_MODE") && nodeContains(step, "verify"):
			bundleIndex = index
		case stepName(step) == finalStep:
			publishIndex = index
		}
	}
	if tagIndex < 0 || bundleIndex <= tagIndex || publishIndex <= bundleIndex {
		fail("release job %s must verify immutable tag, then exact bundle, before channel publication", jobID)
	}
}

func requireEmptyPublicationCredentials(step *yaml.Node, label string, keys ...string) {
	environment := value(step, "env")
	for _, key := range keys {
		entry := value(environment, key)
		if entry == nil || scalar(entry) != "" {
			fail("%s must explicitly clear %s", label, key)
		}
	}
}

func requireNoPublicationCredentials(step *yaml.Node, label string) {
	requireEmptyPublicationCredentials(step, label, "GITHUB_TOKEN", "GH_TOKEN", "HOMEBREW_TAP_TOKEN")
}

func countNodeText(node *yaml.Node, text string) int {
	if node == nil {
		return 0
	}
	count := 0
	if strings.Contains(node.Value, text) {
		count++
	}
	for _, child := range node.Content {
		count += countNodeText(child, text)
	}
	return count
}

func hasCredentialReferenceBeyondEmptyOverride(job *yaml.Node, key string) bool {
	if nodeContains(value(job, "env"), key) {
		return true
	}
	for _, step := range steps(job) {
		allowedReferences := 0
		if entry := value(value(step, "env"), key); entry != nil && scalar(entry) == "" {
			allowedReferences = 1
		}
		if countNodeText(step, key) > allowedReferences {
			return true
		}
	}
	return false
}

func validateRelease(workflow *yaml.Node) {
	requirePermissions(workflow, "release workflow", map[string]string{"contents": "read"})
	concurrency := requiredValue(workflow, "concurrency")
	if scalar(value(concurrency, "cancel-in-progress")) != "false" || !strings.Contains(scalar(value(concurrency, "group")), "github.ref_name") {
		fail("release workflow requires non-canceling tag-scoped concurrency")
	}
	jobs := requiredValue(workflow, "jobs")
	for _, id := range []string{"build-and-test", "publish-github", "publish-homebrew"} {
		if value(jobs, id) == nil {
			fail("release workflow is missing required job %q", id)
		}
	}
	if value(jobs, "attest") != nil || nodeContains(workflow, "attest-build-provenance") {
		fail("release workflow must not use GitHub-native attestation from Depot CI")
	}
	requireGoToolchain(requiredValue(jobs, "build-and-test"), "release build-and-test")
	requireNoPublicationCredentials(findStep(requiredValue(jobs, "build-and-test"), "Build deterministic release bundle"), "release build step")

	github := requiredValue(jobs, "publish-github")
	requireExactSet(value(github, "needs"), "publish-github dependencies", "build-and-test")
	requirePermissions(github, "publish-github job", map[string]string{"contents": "write"})
	requireJobEnvironment(github, "publish-github")
	if hasCredentialReferenceBeyondEmptyOverride(github, "HOMEBREW_TAP_TOKEN") {
		fail("GitHub publication job must never receive the tap token")
	}
	githubPublish := findStep(github, "Publish GitHub release")
	if !nodeContains(githubPublish, "publish-github") || !nodeContains(githubPublish, "github.token") {
		fail("GitHub publication step is not locked to its explicit channel and token")
	}
	requireEmptyPublicationCredentials(githubPublish, "GitHub publication step", "GH_TOKEN", "HOMEBREW_TAP_TOKEN")
	// github.token is job-scoped by the platform, so it is not modeled as a
	// repository secret here; the protected job still verifies before use.
	if !nodeContains(github, "RELEASE_MODE") || !nodeContains(github, "verify") {
		fail("GitHub publication job does not verify the exact bundle")
	}
	validatePublicationOrder(github, "publish-github", "Publish GitHub release")
	validateTokenReferenceBoundary(github, "publish-github", "github.token", "Publish GitHub release")
	requireNoPublicationCredentials(findStep(github, "Verify exact GitHub publication state"), "GitHub pre-publication verification step")

	homebrew := requiredValue(jobs, "publish-homebrew")
	requireExactSet(value(homebrew, "needs"), "publish-homebrew dependencies", "publish-github")
	requirePermissions(homebrew, "publish-homebrew job", map[string]string{"contents": "read"})
	requireJobEnvironment(homebrew, "publish-homebrew")
	if hasCredentialReferenceBeyondEmptyOverride(homebrew, "GITHUB_TOKEN") || hasCredentialReferenceBeyondEmptyOverride(homebrew, "GH_TOKEN") || nodeContains(homebrew, "github.token") || nodeContains(homebrew, "contents: write") {
		fail("Homebrew publication job must not receive GitHub publication authority")
	}
	finalName := "Publish Homebrew formula"
	homebrewPublish := findStep(homebrew, finalName)
	if !nodeContains(homebrewPublish, "publish-homebrew") {
		fail("Homebrew publication step is not locked to its explicit channel")
	}
	requireEmptyPublicationCredentials(homebrewPublish, "Homebrew publication step", "GITHUB_TOKEN", "GH_TOKEN")
	validatePublicationOrder(homebrew, "publish-homebrew", finalName)
	validateSecretBoundary(homebrew, "publish-homebrew", "HOMEBREW_TAP_TOKEN", finalName)
	requireNoPublicationCredentials(findStep(homebrew, "Verify exact Homebrew publication state"), "Homebrew pre-publication verification step")
}

func main() {
	ciPath := ".depot/workflows/ci.yml"
	releasePath := ".depot/workflows/release.yml"
	ci := parse(ciPath)
	release := parse(releasePath)
	validatePinnedActions(ciPath, ci)
	validatePinnedActions(releasePath, release)
	validateCI(ci)
	validateRelease(release)
	fmt.Println("CI and release workflow dependency/privilege contract passed")
}
