package repository

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"

	"github.com/adversarylabs/adversary/internal/archiveutil"
	"github.com/adversarylabs/adversary/internal/publock"
	"github.com/adversarylabs/adversary/pkg/blobsource"
)

const maxLifecycleEntries = 100000

var gcStepHook func(string) error
var gcRemoveHook func(string) error

type GCPlan struct {
	ID               string            `json:"id"`
	References       map[string]string `json:"references"`
	Universe         []Record          `json:"universe"`
	ProtectedContent []string          `json:"protectedContent"`
	Delete           []Record          `json:"delete"`
	DeleteContent    []ContentAction   `json:"deleteContent"`
}
type ContentAction struct{ Kind, Digest string }

type GCReport struct {
	PlanID              string   `json:"planId"`
	DryRun              bool     `json:"dryRun"`
	PlannedRecords      []string `json:"plannedRecords"`
	DeletedRecords      []string `json:"deletedRecords"`
	DeletedContent      []string `json:"deletedContent"`
	DeletedMaterialized []string `json:"deletedMaterialized"`
}

type CheckReport struct {
	Records    []RecordCheck     `json:"records"`
	References map[string]string `json:"references"`
	Healthy    bool              `json:"healthy"`
}

type RecordCheck struct {
	Digest           string `json:"digest"`
	Missing, Corrupt []string
}
type RepairReport struct{ Repaired, Unresolved []string }
type MigrationStatus struct {
	Name       string
	Checkpoint Checkpoint
	Complete   bool
	Remaining  int
}
type gcJournal struct {
	Plan    GCPlan            `json:"plan"`
	Phases  map[string]int    `json:"phases"`
	Content map[string]string `json:"content"`
}

func (r Repository) PlanGC() (GCPlan, error) {
	refs, err := r.referenceSnapshot()
	if err != nil {
		return GCPlan{}, err
	}
	reachable := map[string]bool{}
	for _, digest := range refs {
		reachable[digest] = true
	}
	records, err := r.scanAllRecords()
	if err != nil {
		return GCPlan{}, err
	}
	plan := GCPlan{References: refs, Universe: records}
	for _, rec := range records {
		if !reachable[rec.Digest] {
			plan.Delete = append(plan.Delete, rec)
		} else {
			for _, c := range recordContent(rec) {
				if c.digest != "" {
					plan.ProtectedContent = append(plan.ProtectedContent, c.digest)
				}
			}
		}
	}
	plan.ProtectedContent = unique(plan.ProtectedContent)
	protected := map[string]bool{}
	for _, d := range plan.ProtectedContent {
		protected[d] = true
	}
	seenContent := map[string]bool{}
	for _, rec := range plan.Delete {
		for _, c := range recordContent(rec) {
			if c.digest == "" || protected[c.digest] {
				continue
			}
			k := c.kind + "\x00" + c.digest
			if !seenContent[k] {
				seenContent[k] = true
				plan.DeleteContent = append(plan.DeleteContent, ContentAction{c.kind, c.digest})
			}
		}
	}
	sort.Slice(plan.DeleteContent, func(i, j int) bool {
		if plan.DeleteContent[i].Kind == plan.DeleteContent[j].Kind {
			return plan.DeleteContent[i].Digest < plan.DeleteContent[j].Digest
		}
		return plan.DeleteContent[i].Kind < plan.DeleteContent[j].Kind
	})
	plan.ID = gcPlanID(plan)
	return plan, nil
}

func (r Repository) ApplyGC(plan GCPlan, dryRun bool) (GCReport, error) {
	if plan.ID == "" || plan.ID != gcPlanID(plan) {
		return GCReport{}, fmt.Errorf("invalid GC plan identity")
	}
	report := GCReport{PlanID: plan.ID, DryRun: dryRun}
	for _, rec := range plan.Delete {
		report.PlannedRecords = append(report.PlannedRecords, rec.Digest)
	}
	sort.Strings(report.PlannedRecords)
	if dryRun {
		return report, nil
	}
	lock, err := publock.Acquire(r.Root, "repo-lifecycle")
	if err != nil {
		return report, err
	}
	defer lock.Close()
	journalPath := "checkpoints/gc-" + key(plan.ID) + ".json"
	var journal gcJournal
	journalData, journalErr := r.read(journalPath)
	if journalErr == nil {
		if json.Unmarshal(journalData, &journal) != nil || validateGCJournal(journal, plan) != nil || r.validateGCJournalState(journal) != nil {
			return report, fmt.Errorf("corrupt GC journal")
		}
	} else if os.IsNotExist(journalErr) {
		fresh, freshErr := r.PlanGC()
		if freshErr != nil {
			return report, freshErr
		}
		if fresh.ID != plan.ID {
			return report, ErrCAS
		}
		journal.Plan = plan
		journal.Phases = map[string]int{}
		journal.Content = map[string]string{}
		for _, rec := range plan.Delete {
			journal.Phases[rec.Digest] = 0
		}
		for _, content := range plan.DeleteContent {
			journal.Content[content.Kind+"\x00"+content.Digest] = "pending"
		}
		data, _ := json.Marshal(journal)
		if err := r.atomic(journalPath, data); err != nil {
			return report, err
		}
	} else {
		return report, journalErr
	}
	refs, err := r.referenceSnapshot()
	if err != nil {
		return report, err
	}
	progressed := false
	for _, phase := range journal.Phases {
		if phase > 0 {
			progressed = true
		}
	}
	if !equalStringMap(refs, plan.References) && !progressed {
		return report, ErrCAS
	}
	for _, rec := range plan.Delete {
		if journal.Phases[rec.Digest] > 0 {
			continue
		}
		if refsContains(refs, rec.Digest) {
			return report, ErrCAS
		}
		current, loadErr := r.loadRecord(rec.Digest, false)
		if loadErr != nil || current != rec {
			return report, fmt.Errorf("GC candidate changed or corrupt: %s", rec.Digest)
		}
	}
	if gcStepHook != nil {
		if hookErr := gcStepHook("preflight"); hookErr != nil {
			return report, hookErr
		}
	}
	root, err := os.OpenRoot(r.Root)
	if err != nil {
		return report, err
	}
	defer root.Close()
	for _, rec := range plan.Delete {
		phase := journal.Phases[rec.Digest]
		digestLock, err := publock.Acquire(r.Root, "repo-digest\x00"+rec.Digest)
		if err != nil {
			return report, err
		}
		materializeLock, err := publock.Acquire(r.Root, "repo-materialize\x00"+rec.Digest)
		if err != nil {
			digestLock.Close()
			return report, err
		}
		materialized := "materialized/" + key(rec.Digest)
		if materializedRoot, openErr := root.OpenRoot(materialized); openErr == nil {
			_ = archiveutil.Unseal(materializedRoot)
			_ = materializedRoot.Close()
		}
		if phase < 1 {
			if gcRemoveHook != nil {
				if hookErr := gcRemoveHook(materialized); hookErr != nil {
					materializeLock.Close()
					digestLock.Close()
					return report, hookErr
				}
			}
			if err := root.RemoveAll(materialized); err != nil {
				materializeLock.Close()
				digestLock.Close()
				return report, err
			}
			phase = 1
			if err := r.saveGCPhase(journalPath, &journal, rec.Digest, phase, "materialization"); err != nil {
				materializeLock.Close()
				digestLock.Close()
				return report, err
			}
		}
		report.DeletedMaterialized = append(report.DeletedMaterialized, rec.Digest)
		if phase < 2 {
			currentRefs, refErr := r.referenceSnapshot()
			if refErr != nil {
				materializeLock.Close()
				digestLock.Close()
				return report, refErr
			}
			if refsContains(currentRefs, rec.Digest) {
				materializeLock.Close()
				digestLock.Close()
				return report, ErrCAS
			}
			rel := "commits/" + key(rec.Digest) + ".json"
			if err := root.Remove(rel); err != nil && !os.IsNotExist(err) {
				materializeLock.Close()
				digestLock.Close()
				return report, err
			}
			phase = 2
			if err := r.saveGCPhase(journalPath, &journal, rec.Digest, phase, "commit"); err != nil {
				materializeLock.Close()
				digestLock.Close()
				return report, err
			}
		}
		if phase < 3 {
			rel := "records/" + key(rec.Digest) + ".json"
			if err := root.Remove(rel); err != nil && !os.IsNotExist(err) {
				materializeLock.Close()
				digestLock.Close()
				return report, err
			}
			phase = 3
			if err := r.saveGCPhase(journalPath, &journal, rec.Digest, phase, "record"); err != nil {
				materializeLock.Close()
				digestLock.Close()
				return report, err
			}
		}
		report.DeletedRecords = append(report.DeletedRecords, rec.Digest)
		materializeLock.Close()
		digestLock.Close()
	}
	for _, action := range plan.DeleteContent {
		contentKey := action.Kind + "\x00" + action.Digest
		if journal.Content[contentKey] != "pending" {
			if journal.Content[contentKey] == "deleted" {
				report.DeletedContent = append(report.DeletedContent, action.Digest)
			}
			continue
		}
		currentProtected, protectErr := r.currentGCProtected(plan)
		if protectErr != nil {
			return report, protectErr
		}
		status := "retained"
		if !currentProtected[action.Digest] {
			contentLock, lockErr := publock.Acquire(r.Root, "repo-content\x00"+action.Digest)
			if lockErr != nil {
				return report, lockErr
			}
			rel := action.Kind + "/" + key(action.Digest)
			if gcRemoveHook != nil {
				if hookErr := gcRemoveHook(rel); hookErr != nil {
					contentLock.Close()
					return report, hookErr
				}
			}
			if removeErr := root.Remove(rel); removeErr != nil && !os.IsNotExist(removeErr) {
				contentLock.Close()
				return report, removeErr
			}
			contentLock.Close()
			status = "deleted"
			report.DeletedContent = append(report.DeletedContent, action.Digest)
		} else if verifyErr := r.verifyContent(action.Kind, action.Digest); verifyErr != nil {
			return report, fmt.Errorf("retained content %s failed verification: %w", action.Digest, verifyErr)
		}
		journal.Content[contentKey] = status
		if err := r.saveGCJournal(journalPath, &journal, "content"); err != nil {
			return report, err
		}
	}
	_ = root.Remove(journalPath)
	sort.Strings(report.DeletedRecords)
	sort.Strings(report.DeletedContent)
	sort.Strings(report.DeletedMaterialized)
	return report, nil
}

func validateGCJournal(j gcJournal, plan GCPlan) error {
	if j.Plan.ID == "" || gcPlanID(j.Plan) != j.Plan.ID || !reflect.DeepEqual(j.Plan, plan) || len(j.Phases) != len(plan.Delete) || len(j.Content) != len(plan.DeleteContent) {
		return fmt.Errorf("journal plan mismatch")
	}
	allowed := map[string]bool{}
	for _, rec := range plan.Delete {
		allowed[rec.Digest] = true
	}
	for digest, phase := range j.Phases {
		if !allowed[digest] || phase < 0 || phase > 3 {
			return fmt.Errorf("invalid journal phase")
		}
	}
	allowedContent := map[string]bool{}
	for _, action := range plan.DeleteContent {
		allowedContent[action.Kind+"\x00"+action.Digest] = true
	}
	for k, status := range j.Content {
		if !allowedContent[k] || (status != "pending" && status != "deleted" && status != "retained") {
			return fmt.Errorf("invalid journal content action")
		}
	}
	for digest := range allowed {
		if _, ok := j.Phases[digest]; !ok {
			return fmt.Errorf("missing journal phase")
		}
	}
	return nil
}

func (r Repository) validateGCJournalState(j gcJournal) error {
	for _, rec := range j.Plan.Delete {
		phase := j.Phases[rec.Digest]
		if phase >= 1 {
			if _, err := os.Stat(filepath.Join(r.Root, "materialized", key(rec.Digest))); !os.IsNotExist(err) {
				return fmt.Errorf("journal materialization phase mismatch")
			}
		}
		if phase >= 2 {
			if _, err := r.read("commits/" + key(rec.Digest) + ".json"); !os.IsNotExist(err) {
				return fmt.Errorf("journal commit phase mismatch")
			}
		}
		if phase >= 3 {
			if _, err := r.read("records/" + key(rec.Digest) + ".json"); !os.IsNotExist(err) {
				return fmt.Errorf("journal record phase mismatch")
			}
		} else {
			if _, err := r.read("records/" + key(rec.Digest) + ".json"); err != nil {
				return fmt.Errorf("journal record missing before deletion")
			}
		}
	}
	reachable, err := r.currentGCProtected(j.Plan)
	if err != nil {
		return err
	}
	for _, action := range j.Plan.DeleteContent {
		status := j.Content[action.Kind+"\x00"+action.Digest]
		_, statErr := os.Stat(filepath.Join(r.Root, action.Kind, key(action.Digest)))
		if status == "deleted" && !os.IsNotExist(statErr) && !reachable[action.Digest] {
			return fmt.Errorf("journal deleted content remains")
		}
		if status == "retained" && !reachable[action.Digest] {
			return fmt.Errorf("journal retained content is not reachable")
		}
		if status == "retained" {
			if verifyErr := r.verifyContent(action.Kind, action.Digest); verifyErr != nil {
				return fmt.Errorf("journal retained content failed verification: %w", verifyErr)
			}
		}
	}
	return nil
}

func (r Repository) currentGCProtected(plan GCPlan) (map[string]bool, error) {
	if _, err := r.referenceSnapshot(); err != nil {
		return nil, err
	}
	records, err := r.enumerateAll()
	if err != nil {
		return nil, err
	}
	deleting := map[string]bool{}
	for _, rec := range plan.Delete {
		deleting[rec.Digest] = true
	}
	retained := records[:0]
	for _, rec := range records {
		if !deleting[rec.Digest] {
			retained = append(retained, rec)
		}
	}
	return contentSet(retained), nil
}

func (r Repository) CheckAll() (CheckReport, error) {
	refs, err := r.referenceSnapshot()
	if err != nil {
		return CheckReport{}, err
	}
	records, err := r.scanAllRecords()
	if err != nil {
		return CheckReport{}, err
	}
	report := CheckReport{References: refs, Healthy: true}
	for _, rec := range records {
		v := r.Verify(rec)
		sort.Strings(v.Missing)
		sort.Strings(v.Corrupt)
		report.Records = append(report.Records, RecordCheck{Digest: rec.Digest, Missing: v.Missing, Corrupt: v.Corrupt})
		if len(v.Missing)+len(v.Corrupt) > 0 {
			report.Healthy = false
		}
	}
	for _, digest := range refs {
		if _, err := r.loadRecord(digest, true); err != nil {
			return CheckReport{}, fmt.Errorf("reference target corrupt or missing: %w", err)
		}
	}
	return report, nil
}

func (r Repository) RepairAll(sources map[string]blobsource.Source) (RepairReport, error) {
	report := RepairReport{}
	lifecycle, err := publock.Acquire(r.Root, "repo-lifecycle")
	if err != nil {
		return report, err
	}
	defer lifecycle.Close()
	records, err := r.scanRecords(false)
	if err != nil {
		return report, err
	}
	for _, rec := range records {
		repaired, err := r.repairLocked(rec, sources)
		if err != nil {
			report.Unresolved = append(report.Unresolved, rec.Digest)
			continue
		}
		if repaired {
			report.Repaired = append(report.Repaired, rec.Digest)
		}
	}
	sort.Strings(report.Repaired)
	sort.Strings(report.Unresolved)
	return report, nil
}

func (r Repository) MigrationStatus(name string) (MigrationStatus, error) {
	cp, err := r.LoadCheckpoint(name)
	if err != nil && !os.IsNotExist(err) {
		return MigrationStatus{}, err
	}
	all, enumErr := r.enumerateAll()
	if enumErr != nil {
		return MigrationStatus{}, enumErr
	}
	remaining := 0
	for _, rec := range all {
		if rec.Digest > cp.LastDigest {
			remaining++
		}
	}
	return MigrationStatus{Name: name, Checkpoint: cp, Complete: remaining == 0, Remaining: remaining}, nil
}

func (r Repository) saveGCPhase(path string, j *gcJournal, digest string, phase int, label string) error {
	j.Phases[digest] = phase
	return r.saveGCJournal(path, j, label)
}
func (r Repository) saveGCJournal(path string, j *gcJournal, label string) error {
	data, _ := json.Marshal(j)
	if err := r.atomic(path, data); err != nil {
		return err
	}
	if gcStepHook != nil {
		return gcStepHook(label)
	}
	return nil
}

func (r Repository) enumerateAll() ([]Record, error) {
	var out []Record
	after := ""
	for {
		page, err := r.Enumerate(after, 1000)
		if err != nil {
			return nil, err
		}
		if len(page) == 0 {
			break
		}
		out = append(out, page...)
		after = page[len(page)-1].Digest
		if len(out) > maxLifecycleEntries {
			return nil, fmt.Errorf("repository exceeds bounded lifecycle limit")
		}
	}
	return out, nil
}

func (r Repository) scanAllRecords() ([]Record, error) {
	return r.scanRecords(true)
}

func (r Repository) scanRecords(validateContent bool) ([]Record, error) {
	root, err := os.OpenRoot(r.Root)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	dir, err := root.Open("records")
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	var out []Record
	for {
		entries, e := dir.ReadDir(128)
		if e != nil && e != io.EOF {
			return nil, e
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			if len(out) >= maxLifecycleEntries {
				return nil, fmt.Errorf("repository exceeds bounded lifecycle limit")
			}
			data, readErr := r.read("records/" + entry.Name())
			if readErr != nil {
				return nil, readErr
			}
			var rec Record
			if json.Unmarshal(data, &rec) != nil || rec.Digest == "" || entry.Name() != key(rec.Digest)+".json" {
				return nil, fmt.Errorf("malformed repository record")
			}
			canonical, loadErr := r.loadRecordMetadata(rec.Digest, false)
			if loadErr != nil || canonical != rec {
				return nil, fmt.Errorf("corrupt repository record %s", rec.Digest)
			}
			if validateContent {
				if _, loadErr := r.loadRecord(rec.Digest, false); loadErr != nil {
					return nil, fmt.Errorf("corrupt repository record %s", rec.Digest)
				}
			}
			out = append(out, rec)
		}
		if e == io.EOF {
			break
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Digest < out[j].Digest })
	return out, nil
}

func (r Repository) referenceSnapshot() (map[string]string, error) {
	root, err := os.OpenRoot(r.Root)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	dir, err := root.Open("refs")
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	out := map[string]string{}
	count := 0
	for {
		entries, e := dir.ReadDir(128)
		if e != nil && e != io.EOF {
			return nil, e
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			count++
			if count > maxLifecycleEntries {
				return nil, fmt.Errorf("repository exceeds bounded reference limit")
			}
			data, readErr := r.read("refs/" + entry.Name())
			if readErr != nil {
				return nil, readErr
			}
			var idx struct{ Reference, Digest string }
			if json.Unmarshal(data, &idx) != nil || idx.Reference == "" || idx.Digest == "" || entry.Name() != key(idx.Reference)+".json" {
				return nil, fmt.Errorf("corrupt reference index")
			}
			if _, loadErr := r.loadRecord(idx.Digest, true); loadErr != nil {
				return nil, fmt.Errorf("corrupt reference target: %w", loadErr)
			}
			out[idx.Reference] = idx.Digest
		}
		if e == io.EOF {
			break
		}
	}
	return out, nil
}

func (r Repository) recordsForDigests(refs map[string]string) ([]Record, error) {
	seen := map[string]bool{}
	var out []Record
	for _, d := range refs {
		if seen[d] {
			continue
		}
		seen[d] = true
		rec, e := r.loadRecord(d, true)
		if e != nil {
			return nil, e
		}
		out = append(out, rec)
	}
	return out, nil
}

type contentRef struct{ kind, digest string }

func recordContent(r Record) []contentRef {
	return []contentRef{{"manifests", r.ManifestDigest}, {"blobs", r.ConfigDigest}, {"blobs", r.LayerDigest}, {"adversary-manifests", r.AdversaryManifestDigest}}
}
func contentSet(records []Record) map[string]bool {
	m := map[string]bool{}
	for _, r := range records {
		for _, c := range recordContent(r) {
			if c.digest != "" {
				m[c.digest] = true
			}
		}
	}
	return m
}
func refsContains(refs map[string]string, d string) bool {
	for _, v := range refs {
		if v == d {
			return true
		}
	}
	return false
}
func equalStringMap(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
func gcPlanID(p GCPlan) string {
	clone := p
	clone.ID = ""
	data, _ := json.Marshal(clone)
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}
