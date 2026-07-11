package repository

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/adversarylabs/adversary/pkg/oci"
	"github.com/adversarylabs/adversary/pkg/pack"
)

func sharedContentArtifact(t *testing.T, a pack.Artifact, marker string) pack.Artifact {
	t.Helper()
	b := a
	m := a.OCIManifest
	m.Annotations = map[string]string{}
	for k, v := range a.OCIManifest.Annotations {
		m.Annotations[k] = v
	}
	m.Annotations["test.marker"] = marker
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	b.OCIManifest = m
	b.Manifest = data
	b.ManifestDigest = oci.Digest(data)
	return b
}

func TestGCPlanApplyPreservesReachableAndDeletesUnreachable(t *testing.T) {
	r := Repository{Root: t.TempDir()}
	keep, err := r.ImportPacked(artifact(t, "keep"), "keep.example/team/test:1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	drop, err := r.ImportPacked(artifact(t, "drop"), "drop.example/team/test:1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	materialized, err := r.Materialize(drop)
	if err != nil {
		t.Fatal(err)
	}
	makeWritable(materialized)
	if err := r.DeleteRef("drop.example/team/test:1.0.0", drop.Digest); err != nil {
		t.Fatal(err)
	}
	plan, err := r.PlanGC()
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Delete) != 1 || plan.Delete[0].Digest != drop.Digest {
		t.Fatalf("plan=%#v", plan)
	}
	dry, err := r.ApplyGC(plan, true)
	if err != nil || !dry.DryRun {
		t.Fatalf("dry=%#v err=%v", dry, err)
	}
	if _, err := r.Resolve(drop.Digest); err != nil {
		t.Fatal("dry run mutated repository")
	}
	report, err := r.ApplyGC(plan, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.DeletedRecords) != 1 || report.DeletedRecords[0] != drop.Digest {
		t.Fatalf("report=%#v", report)
	}
	if _, err := r.Resolve(keep.Digest); err != nil {
		t.Fatal("reachable record deleted")
	}
	if _, err := r.Resolve(drop.Digest); !os.IsNotExist(err) {
		t.Fatalf("unreachable resolve err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(r.Root, "materialized", key(drop.Digest))); !os.IsNotExist(err) {
		t.Fatalf("materialization remains: %v", err)
	}
}

func TestGCResumeRejectsCandidateReferencedAfterMaterializationPhase(t *testing.T) {
	r := Repository{Root: t.TempDir()}
	rec, err := r.ImportPacked(artifact(t, "one"), "")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := r.PlanGC()
	if err != nil {
		t.Fatal(err)
	}
	failed := false
	gcStepHook = func(step string) error {
		if step == "materialization" && !failed {
			failed = true
			return errors.New("crash")
		}
		return nil
	}
	if _, err := r.ApplyGC(plan, false); err == nil {
		t.Fatal("expected crash")
	}
	gcStepHook = nil
	if err := r.UpdateRef("registry.example/team/test:1.0.0", "", rec.Digest); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ApplyGC(plan, false); !errors.Is(err, ErrCAS) {
		t.Fatalf("resume err=%v", err)
	}
	if _, err := r.Resolve(rec.Digest); err != nil {
		t.Fatal("newly reachable candidate removed")
	}
}

func TestGCJournalValidationRejectsForgery(t *testing.T) {
	for _, kind := range []string{"unknown", "missing", "phase", "phase1-untouched", "content-deleted", "content-retained", "plan"} {
		t.Run(kind, func(t *testing.T) {
			r := Repository{Root: t.TempDir()}
			t.Cleanup(func() { makeWritable(r.Root) })
			rec, err := r.ImportPacked(artifact(t, "one"), "")
			if err != nil {
				t.Fatal(err)
			}
			if kind == "phase1-untouched" {
				if _, err := r.Materialize(rec); err != nil {
					t.Fatal(err)
				}
			}
			plan, err := r.PlanGC()
			if err != nil {
				t.Fatal(err)
			}
			gcStepHook = func(string) error { return errors.New("stop") }
			_, _ = r.ApplyGC(plan, false)
			gcStepHook = nil
			path := filepath.Join(r.Root, "checkpoints", "gc-"+key(plan.ID)+".json")
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var j gcJournal
			if json.Unmarshal(data, &j) != nil {
				t.Fatal("decode")
			}
			switch kind {
			case "unknown":
				j.Phases["sha256:unknown"] = 0
			case "missing":
				for d := range j.Phases {
					delete(j.Phases, d)
					break
				}
			case "phase":
				for d := range j.Phases {
					j.Phases[d] = 9
					break
				}
			case "phase1-untouched":
				for d := range j.Phases {
					j.Phases[d] = 1
				}
			case "content-deleted", "content-retained":
				for d := range j.Phases {
					j.Phases[d] = 3
				}
				for k := range j.Content {
					if kind == "content-deleted" {
						j.Content[k] = "deleted"
					} else {
						j.Content[k] = "retained"
					}
				}
			case "plan":
				j.Plan.Delete = nil
			}
			data, _ = json.Marshal(j)
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := r.ApplyGC(plan, false); err == nil {
				t.Fatal("forged journal accepted")
			}
		})
	}
}

func TestGCJournalRetainedContentMustExistAndVerify(t *testing.T) {
	for _, mode := range []string{"missing", "corrupt"} {
		t.Run(mode, func(t *testing.T) {
			r := Repository{Root: t.TempDir()}
			base := artifact(t, "shared")
			a := sharedContentArtifact(t, base, "a")
			if _, err := r.ImportPacked(a, ""); err != nil {
				t.Fatal(err)
			}
			plan, err := r.PlanGC()
			if err != nil {
				t.Fatal(err)
			}
			gcStepHook = func(string) error { return errors.New("stop") }
			_, _ = r.ApplyGC(plan, false)
			gcStepHook = nil
			live := sharedContentArtifact(t, base, "live")
			if _, err := r.ImportPacked(live, "registry.example/team/live:1.0.0"); err != nil {
				t.Fatal(err)
			}
			journalPath := filepath.Join(r.Root, "checkpoints", "gc-"+key(plan.ID)+".json")
			data, err := os.ReadFile(journalPath)
			if err != nil {
				t.Fatal(err)
			}
			var journal gcJournal
			if json.Unmarshal(data, &journal) != nil {
				t.Fatal("decode")
			}
			action := plan.DeleteContent[0]
			journal.Content[action.Kind+"\x00"+action.Digest] = "retained"
			data, _ = json.Marshal(journal)
			if err := os.WriteFile(journalPath, data, 0600); err != nil {
				t.Fatal(err)
			}
			contentPath := filepath.Join(r.Root, action.Kind, key(action.Digest))
			if mode == "missing" {
				if err := os.Remove(contentPath); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.Chmod(contentPath, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(contentPath, []byte("corrupt"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := r.ApplyGC(plan, false); err == nil {
				t.Fatal("invalid retained content accepted")
			}
		})
	}
}

func TestMaterializationLeaseBlocksGC(t *testing.T) {
	r := Repository{Root: t.TempDir()}
	rec, err := r.ImportPacked(artifact(t, "one"), "")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := r.PlanGC()
	if err != nil {
		t.Fatal(err)
	}
	lease, err := r.LeaseMaterialized(rec)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := r.ApplyGC(plan, false); done <- err }()
	select {
	case err := <-done:
		t.Fatalf("GC completed while lease held: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if _, err := os.Stat(filepath.Join(lease.Path, "dist/index.js")); err != nil {
		t.Fatal("leased tree unavailable")
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestGCRemovalFailureReleasesLocksForLease(t *testing.T) {
	r := Repository{Root: t.TempDir()}
	t.Cleanup(func() { makeWritable(r.Root) })
	rec, err := r.ImportPacked(artifact(t, "one"), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Materialize(rec); err != nil {
		t.Fatal(err)
	}
	plan, err := r.PlanGC()
	if err != nil {
		t.Fatal(err)
	}
	gcRemoveHook = func(string) error { return errors.New("remove failed") }
	if _, err := r.ApplyGC(plan, false); err == nil {
		t.Fatal("injection did not fail")
	}
	gcRemoveHook = nil
	done := make(chan error, 1)
	go func() {
		lease, err := r.LeaseMaterialized(rec)
		if err == nil {
			err = lease.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("lease deadlocked after removal failure")
	}
}

func TestWithMaterializedPureRuntimeCallback(t *testing.T) {
	r := Repository{Root: t.TempDir()}
	t.Cleanup(func() { makeWritable(r.Root) })
	rec, err := r.ImportPacked(artifact(t, "one"), "")
	if err != nil {
		t.Fatal(err)
	}
	if err := r.WithMaterialized(rec, func(path string) error { _, err := os.Stat(filepath.Join(path, "dist/index.js")); return err }); err != nil {
		t.Fatal(err)
	}
}

func TestGCPlanCASAndCorruptionFailClosed(t *testing.T) {
	r := Repository{Root: t.TempDir()}
	rec, err := r.ImportPacked(artifact(t, "one"), "")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := r.PlanGC()
	if err != nil {
		t.Fatal(err)
	}
	if err := r.UpdateRef("registry.example/team/test:1.0.0", "", rec.Digest); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ApplyGC(plan, false); !errors.Is(err, ErrCAS) {
		t.Fatalf("err=%v", err)
	}
	if _, err := r.Resolve(rec.Digest); err != nil {
		t.Fatal("CAS failure deleted record")
	}
	if err := os.WriteFile(filepath.Join(r.Root, "refs", key("bad")+".json"), []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := r.PlanGC(); err == nil {
		t.Fatal("corrupt reference accepted")
	}
}

func TestCheckRepairAndMigrationStatus(t *testing.T) {
	r := Repository{Root: t.TempDir()}
	a := artifact(t, "one")
	rec, err := r.ImportPacked(a, "registry.example/team/test:1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(r.content("blobs", rec.LayerDigest), []byte("bad"), 0600); err != nil {
		t.Fatal(err)
	}
	check, err := r.CheckAll()
	if err != nil || check.Healthy {
		t.Fatalf("check=%#v err=%v", check, err)
	}
	repaired, err := r.RepairAll(map[string][]byte{rec.LayerDigest: a.Layer})
	if err != nil || len(repaired.Repaired) != 1 {
		t.Fatalf("repair=%#v err=%v", repaired, err)
	}
	if err := r.SaveCheckpoint("legacy", Checkpoint{LastDigest: rec.Digest, Imported: 1}); err != nil {
		t.Fatal(err)
	}
	status, err := r.MigrationStatus("legacy")
	if err != nil || !status.Complete || status.Checkpoint.Imported != 1 {
		t.Fatalf("status=%#v err=%v", status, err)
	}
}

func TestGCInjectedFailureBeforeMutationIsResumable(t *testing.T) {
	r := Repository{Root: t.TempDir()}
	rec, err := r.ImportPacked(artifact(t, "one"), "")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := r.PlanGC()
	if err != nil {
		t.Fatal(err)
	}
	gcStepHook = func(step string) error { return errors.New("injected crash") }
	if _, err := r.ApplyGC(plan, false); err == nil {
		t.Fatal("injection did not fail")
	}
	gcStepHook = nil
	if _, err := r.Resolve(rec.Digest); err != nil {
		t.Fatal("preflight failure mutated repository")
	}
	if _, err := r.ApplyGC(plan, false); err != nil {
		t.Fatal(err)
	}
}

func TestGCAndReferenceUpdateSerialize(t *testing.T) {
	r := Repository{Root: t.TempDir()}
	rec, err := r.ImportPacked(artifact(t, "one"), "")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := r.PlanGC()
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	release := make(chan struct{})
	gcStepHook = func(step string) error {
		if step == "preflight" {
			close(start)
			<-release
		}
		return nil
	}
	done := make(chan error, 1)
	go func() { _, err := r.ApplyGC(plan, false); done <- err }()
	<-start
	refDone := make(chan error, 1)
	go func() { refDone <- r.UpdateRef("registry.example/team/test:1.0.0", "", rec.Digest) }()
	close(release)
	gcErr := <-done
	refErr := <-refDone
	gcStepHook = nil
	if gcErr != nil {
		t.Fatal(gcErr)
	}
	if refErr == nil {
		t.Fatal("reference update targeted a record deleted under lifecycle lock")
	}
}

func TestGCRejectsPostPlanImportAndSubsetForgery(t *testing.T) {
	r := Repository{Root: t.TempDir()}
	first, err := r.ImportPacked(artifact(t, "one"), "")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := r.PlanGC()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.ImportPacked(artifact(t, "two"), ""); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ApplyGC(plan, false); !errors.Is(err, ErrCAS) {
		t.Fatalf("post-import err=%v", err)
	}
	fresh, err := r.PlanGC()
	if err != nil {
		t.Fatal(err)
	}
	fresh.Delete = nil
	fresh.ID = gcPlanID(fresh)
	if _, err := r.ApplyGC(fresh, false); !errors.Is(err, ErrCAS) {
		t.Fatalf("subset err=%v", err)
	}
	if _, err := r.Resolve(first.Digest); err != nil {
		t.Fatal("forged plan mutated repository")
	}
}

func TestGCJournalResumesEveryPhase(t *testing.T) {
	for _, phase := range []string{"materialization", "commit", "record", "content"} {
		t.Run(phase, func(t *testing.T) {
			r := Repository{Root: t.TempDir()}
			rec, err := r.ImportPacked(artifact(t, phase), "")
			if err != nil {
				t.Fatal(err)
			}
			plan, err := r.PlanGC()
			if err != nil {
				t.Fatal(err)
			}
			failed := false
			gcStepHook = func(step string) error {
				if step == phase && !failed {
					failed = true
					return errors.New("injected")
				}
				return nil
			}
			if _, err := r.ApplyGC(plan, false); err == nil {
				t.Fatal("injection did not fail")
			}
			gcStepHook = nil
			if _, err := r.ApplyGC(plan, false); err != nil {
				t.Fatalf("resume: %v", err)
			}
			if _, err := r.Resolve(rec.Digest); !os.IsNotExist(err) {
				t.Fatalf("resolve err=%v", err)
			}
		})
	}
}

func TestGCSharedContentCrashAndReachabilityRecovery(t *testing.T) {
	for _, mode := range []string{"before-content", "after-first-content", "unreferenced-after-first-content"} {
		t.Run(mode, func(t *testing.T) {
			r := Repository{Root: t.TempDir()}
			base := artifact(t, "shared")
			a := sharedContentArtifact(t, base, "a")
			b := sharedContentArtifact(t, base, "b")
			if _, err := r.ImportPacked(a, ""); err != nil {
				t.Fatal(err)
			}
			if _, err := r.ImportPacked(b, ""); err != nil {
				t.Fatal(err)
			}
			plan, err := r.PlanGC()
			if err != nil {
				t.Fatal(err)
			}
			count := 0
			gcStepHook = func(step string) error {
				if mode == "before-content" && step == "record" {
					count++
					if count == len(plan.Delete) {
						return errors.New("crash")
					}
				}
				if (mode == "after-first-content" || mode == "unreferenced-after-first-content") && step == "content" {
					count++
					if count == 1 {
						return errors.New("crash")
					}
				}
				return nil
			}
			if _, err := r.ApplyGC(plan, false); err == nil {
				t.Fatal("injection did not fail")
			}
			gcStepHook = nil
			live := sharedContentArtifact(t, base, "live")
			ref := "registry.example/team/test:1.0.0"
			if mode == "unreferenced-after-first-content" {
				ref = ""
			}
			liveRec, err := r.ImportPacked(live, ref)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := r.ApplyGC(plan, false); err != nil {
				t.Fatalf("resume: %v", err)
			}
			resolveValue := ref
			if resolveValue == "" {
				resolveValue = liveRec.Digest
			}
			resolved, err := r.Resolve(resolveValue)
			if err != nil || resolved.Digest != liveRec.Digest {
				t.Fatalf("resolved=%#v err=%v", resolved, err)
			}
			if v := r.Verify(liveRec); len(v.Missing)+len(v.Corrupt) > 0 {
				t.Fatalf("live shared content damaged: %#v", v)
			}
		})
	}
}

func TestCheckpointValidationAndCAS(t *testing.T) {
	r := Repository{Root: t.TempDir()}
	if err := r.SaveCheckpoint("bad", Checkpoint{LastDigest: "bad", Imported: -1}); err == nil {
		t.Fatal("malformed checkpoint accepted")
	}
	a := artifact(t, "one")
	cp := Checkpoint{LastDigest: a.ManifestDigest, Imported: 1}
	if err := r.SaveCheckpoint("migration", cp); err != nil {
		t.Fatal(err)
	}
	next := Checkpoint{LastDigest: a.ManifestDigest, Imported: 2}
	if err := r.UpdateCheckpoint("migration", Checkpoint{}, next); !errors.Is(err, ErrCAS) {
		t.Fatalf("stale err=%v", err)
	}
	if err := r.UpdateCheckpoint("migration", cp, next); err != nil {
		t.Fatal(err)
	}
	if err := r.SaveCheckpoint("migration", cp); !errors.Is(err, ErrCAS) {
		t.Fatalf("regression err=%v", err)
	}
}
