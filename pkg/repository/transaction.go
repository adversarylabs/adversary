package repository

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"

	"github.com/adversarylabs/adversary/internal/publock"
	"github.com/adversarylabs/adversary/pkg/oci"
)

type importJournal struct {
	Version          int    `json:"version"`
	Digest           string `json:"digest"`
	Reference        string `json:"reference,omitempty"`
	CreatedRecord    bool   `json:"createdRecord"`
	CreatedCommit    bool   `json:"createdCommit"`
	CreatedReference bool   `json:"createdReference"`
}
type refMutationJournal struct {
	Version   int    `json:"version"`
	Reference string `json:"reference"`
	Previous  string `json:"previous,omitempty"`
	Next      string `json:"next,omitempty"`
	Delete    bool   `json:"delete,omitempty"`
}

var transactionRemoveHook func(string) error
var transactionRebuildHook func() error
var refMutationHook func(string) error

func importJournalPath(digest, ref string) string {
	return "transactions/import-" + key(digest+"\x00"+ref) + ".json"
}
func refMutationJournalPath(ref string) string { return "transactions/ref-" + key(ref) + ".json" }
func (r Repository) saveRefMutationJournal(j refMutationJournal) error {
	data, _ := json.Marshal(j)
	return r.atomic(refMutationJournalPath(j.Reference), data)
}

func (r Repository) readRefMutationJournal(ref string) (refMutationJournal, error) {
	data, err := r.readLimit(refMutationJournalPath(ref), maxIndexBytes)
	if err != nil {
		return refMutationJournal{}, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var j refMutationJournal
	if err := dec.Decode(&j); err != nil || dec.Decode(&struct{}{}) != io.EOF || j.Version != 1 || j.Reference != ref || (j.Delete == (j.Next != "")) {
		return refMutationJournal{}, fmt.Errorf("malformed reference transaction journal")
	}
	canonical, err := r.canonicalRef(j.Reference)
	if err != nil || canonical != j.Reference {
		return refMutationJournal{}, fmt.Errorf("reference transaction journal is not canonical")
	}
	if j.Previous != "" {
		if _, err := oci.ParseDigest(j.Previous); err != nil {
			return refMutationJournal{}, err
		}
		if _, err := r.loadRecordMode(j.Previous, true, true); err != nil {
			return refMutationJournal{}, fmt.Errorf("invalid previous reference target: %w", err)
		}
	}
	if j.Next != "" {
		if _, err := oci.ParseDigest(j.Next); err != nil {
			return refMutationJournal{}, err
		}
		if _, err := r.loadRecordMode(j.Next, true, true); err != nil {
			return refMutationJournal{}, fmt.Errorf("invalid next reference target: %w", err)
		}
	}
	return j, nil
}

func (r Repository) validateRefMutationCurrent(j refMutationJournal) (string, error) {
	current, err := r.referenceDigestRaw(j.Reference)
	if os.IsNotExist(err) {
		current = ""
	} else if err != nil {
		return "", err
	}
	intended := j.Next
	if j.Delete {
		intended = ""
	}
	if current != j.Previous && current != intended {
		return "", errors.Join(ErrCAS, fmt.Errorf("reference transaction ownership changed"))
	}
	return current, nil
}

func (r Repository) refMutationJournals() (map[string]refMutationJournal, error) {
	root, err := os.OpenRoot(r.Root)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	entries, err := fs.ReadDir(root.FS(), "transactions")
	if os.IsNotExist(err) {
		return map[string]refMutationJournal{}, nil
	}
	if err != nil {
		return nil, err
	}
	if len(entries) > maxLifecycleEntries {
		return nil, fmt.Errorf("repository transaction journal exceeds lifecycle limit")
	}
	out := map[string]refMutationJournal{}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "ref-") {
			continue
		}
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() {
			return nil, fmt.Errorf("invalid transaction journal %q", entry.Name())
		}
		data, err := r.readLimit("transactions/"+entry.Name(), maxIndexBytes)
		if err != nil {
			return nil, err
		}
		var envelope struct {
			Reference string `json:"reference"`
		}
		if json.Unmarshal(data, &envelope) != nil || envelope.Reference == "" {
			return nil, fmt.Errorf("malformed reference transaction journal %q", entry.Name())
		}
		j, err := r.readRefMutationJournal(envelope.Reference)
		if err != nil || refMutationJournalPath(j.Reference) != "transactions/"+entry.Name() {
			return nil, fmt.Errorf("malformed reference transaction journal %q", entry.Name())
		}
		out[j.Reference] = j
	}
	return out, nil
}

func (r Repository) saveImportJournal(j importJournal) error {
	data, _ := json.Marshal(j)
	return r.atomic(importJournalPath(j.Digest, j.Reference), data)
}

// Recover rolls back imports that did not reach their acknowledgement point.
// Content blobs are intentionally retained for later repair/deduplication.
func (r Repository) Recover() error {
	if err := r.init(); err != nil {
		return err
	}
	lock, err := publock.Acquire(r.Root, "repo-lifecycle")
	if err != nil {
		return err
	}
	defer lock.Close()
	return r.recoverImportsLocked()
}

func (r Repository) recoverImportsLocked() error {
	root, err := os.OpenRoot(r.Root)
	if err != nil {
		return err
	}
	defer root.Close()
	entries, err := fs.ReadDir(root.FS(), "transactions")
	if err != nil {
		return err
	}
	if len(entries) > maxLifecycleEntries {
		return fmt.Errorf("repository transaction journal exceeds lifecycle limit")
	}
	for _, entry := range entries {
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() {
			return fmt.Errorf("invalid transaction journal %q", entry.Name())
		}
		data, err := r.readLimit("transactions/"+entry.Name(), maxIndexBytes)
		if err != nil {
			return err
		}
		if strings.HasPrefix(entry.Name(), "ref-") {
			var envelope struct {
				Reference string `json:"reference"`
			}
			if json.Unmarshal(data, &envelope) != nil || envelope.Reference == "" {
				return fmt.Errorf("malformed reference transaction journal %q", entry.Name())
			}
			j, readErr := r.readRefMutationJournal(envelope.Reference)
			if readErr != nil || refMutationJournalPath(j.Reference) != "transactions/"+entry.Name() {
				return fmt.Errorf("malformed reference transaction journal %q", entry.Name())
			}
			if err := r.rollbackRefMutation(j); err != nil {
				return err
			}
			continue
		}
		if !strings.HasPrefix(entry.Name(), "import-") {
			return fmt.Errorf("unknown transaction journal %q", entry.Name())
		}
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.DisallowUnknownFields()
		var j importJournal
		if err := dec.Decode(&j); err != nil || dec.Decode(&struct{}{}) != io.EOF || j.Version != 1 || j.Digest == "" || importJournalPath(j.Digest, j.Reference) != "transactions/"+entry.Name() {
			return fmt.Errorf("malformed transaction journal %q", entry.Name())
		}
		if err := r.rollbackImportJournal(j); err != nil {
			return err
		}
	}
	return nil
}

func (r Repository) rollbackRefMutation(j refMutationJournal) error {
	current, currentErr := r.validateRefMutationCurrent(j)
	if currentErr != nil {
		return currentErr
	}
	intended := j.Next
	if j.Delete {
		intended = ""
	}
	if refMutationHook != nil {
		if err := refMutationHook("restore"); err != nil {
			return err
		}
	}
	if current == intended && j.Previous == "" {
		root, err := os.OpenRoot(r.Root)
		if err != nil {
			return err
		}
		err = removeWithRoot(root, "refs/"+key(j.Reference)+".json")
		if closeErr := root.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			return err
		}
	} else if current == intended {
		encoded, _ := json.Marshal(struct{ Reference, Digest string }{j.Reference, j.Previous})
		if err := r.atomic("refs/"+key(j.Reference)+".json", encoded); err != nil {
			return err
		}
	}
	if refMutationHook != nil {
		if err := refMutationHook("reconcile"); err != nil {
			return err
		}
	}
	if err := r.rebuildAliases(); err != nil {
		return err
	}
	root, err := os.OpenRoot(r.Root)
	if err != nil {
		return err
	}
	err = removeWithRoot(root, refMutationJournalPath(j.Reference))
	return errors.Join(err, root.Close())
}

func (r Repository) commitRefMutation(j refMutationJournal) error {
	root, err := os.OpenRoot(r.Root)
	if err != nil {
		return err
	}
	err = removeWithRoot(root, refMutationJournalPath(j.Reference))
	return errors.Join(err, root.Close())
}

func (r Repository) rollbackImportJournal(j importJournal) error {
	root, err := os.OpenRoot(r.Root)
	if err != nil {
		return err
	}
	remove := func(rel string) error {
		if transactionRemoveHook != nil {
			if err := transactionRemoveHook(rel); err != nil {
				return err
			}
		}
		if err := root.Remove(rel); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	var cleanupErr error
	if j.CreatedReference && j.Reference != "" {
		if digest, e := r.referenceDigestRaw(j.Reference); e == nil {
			if digest != j.Digest {
				return errors.Join(fmt.Errorf("journal reference ownership changed"), root.Close())
			} else {
				cleanupErr = errors.Join(cleanupErr, remove("refs/"+key(j.Reference)+".json"))
			}
		} else if !os.IsNotExist(e) {
			cleanupErr = errors.Join(cleanupErr, e)
		}
	}
	if j.CreatedCommit {
		cleanupErr = errors.Join(cleanupErr, remove("commits/"+key(j.Digest)+".json"))
	}
	if j.CreatedRecord {
		cleanupErr = errors.Join(cleanupErr, remove("records/"+key(j.Digest)+".json"))
	}
	cleanupErr = errors.Join(cleanupErr, root.Close())
	if transactionRebuildHook != nil {
		cleanupErr = errors.Join(cleanupErr, transactionRebuildHook())
	}
	if cleanupErr == nil {
		cleanupErr = r.rebuildAliases()
	}
	if cleanupErr != nil {
		return cleanupErr
	}
	root, err = os.OpenRoot(r.Root)
	if err != nil {
		return err
	}
	journalErr := removeWithRoot(root, importJournalPath(j.Digest, j.Reference))
	return errors.Join(journalErr, root.Close())
}

func removeWithRoot(root *os.Root, rel string) error {
	if transactionRemoveHook != nil {
		if err := transactionRemoveHook(rel); err != nil {
			return err
		}
	}
	if err := root.Remove(rel); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (r Repository) pendingImport(digest string) (bool, error) {
	root, err := os.OpenRoot(r.Root)
	if err != nil {
		return false, err
	}
	defer root.Close()
	entries, err := fs.ReadDir(root.FS(), "transactions")
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if len(entries) > maxLifecycleEntries {
		return false, fmt.Errorf("repository transaction journal exceeds lifecycle limit")
	}
	for _, entry := range entries {
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() {
			return false, fmt.Errorf("invalid transaction journal %q", entry.Name())
		}
		data, err := r.readLimit("transactions/"+entry.Name(), maxIndexBytes)
		if err != nil {
			return false, err
		}
		if strings.HasPrefix(entry.Name(), "ref-") {
			continue
		}
		if !strings.HasPrefix(entry.Name(), "import-") {
			return false, fmt.Errorf("unknown transaction journal %q", entry.Name())
		}
		var j importJournal
		if json.Unmarshal(data, &j) != nil || j.Version != 1 || importJournalPath(j.Digest, j.Reference) != "transactions/"+entry.Name() {
			return false, fmt.Errorf("malformed transaction journal %q", entry.Name())
		}
		if j.Digest == digest {
			return true, nil
		}
	}
	return false, nil
}
