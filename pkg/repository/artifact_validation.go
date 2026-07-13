package repository

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"

	"github.com/adversarylabs/adversary/internal/archiveutil"
	"github.com/adversarylabs/adversary/pkg/blobsource"
	canonical "github.com/adversarylabs/adversary/pkg/manifest"
	"github.com/adversarylabs/adversary/pkg/oci"
	"github.com/adversarylabs/adversary/pkg/pack"
)

func validateArtifactLayer(configData, adversary []byte, annotations map[string]string, layer blobsource.Source) ([]byte, error) {
	config, err := pack.DecodeArtifactConfig(configData)
	if err != nil {
		return nil, err
	}
	actual, layerManifest, hasLayerManifest, err := extractLayerInventory(layer)
	if err != nil {
		return nil, fmt.Errorf("validate package layer: %w", err)
	}
	canonicalData := adversary
	if hasLayerManifest {
		if len(adversary) > 0 && !bytes.Equal(adversary, layerManifest) {
			return nil, fmt.Errorf("attached %s conflicts with package-layer copy", canonical.FileName)
		}
		canonicalData = layerManifest
	}
	if len(canonicalData) == 0 {
		return nil, fmt.Errorf("%s is absent from both the attachment and package layer", canonical.FileName)
	}
	manifest, err := canonical.Parse(canonicalData)
	if err != nil {
		return nil, fmt.Errorf("parse canonical %s: %w", canonical.FileName, err)
	}
	if !reflect.DeepEqual(actual, config.Files) {
		return nil, inventoryMismatch(config.Files, actual)
	}
	if err := pack.ValidateArtifactMetadata(config, annotations, manifest, actual); err != nil {
		return nil, fmt.Errorf("cross-check artifact metadata: %w", err)
	}
	return canonicalData, nil
}

func extractLayerInventory(layer blobsource.Source) (_ []pack.File, _ []byte, _ bool, retErr error) {
	if layer == nil {
		return nil, nil, false, fmt.Errorf("package layer source is required")
	}
	if err := blobsource.Verify(layer); err != nil {
		return nil, nil, false, fmt.Errorf("verify package layer: %w", err)
	}
	dir, err := os.MkdirTemp("", "adversary-layer-validation-")
	if err != nil {
		return nil, nil, false, err
	}
	defer func() { retErr = errorsJoin(retErr, os.RemoveAll(dir)) }()
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, nil, false, err
	}
	defer func() { retErr = errorsJoin(retErr, root.Close()) }()
	reader, err := layer.Open()
	if err != nil {
		return nil, nil, false, err
	}
	extractErr := archiveutil.ExtractGzipTar(reader, root, archiveutil.DefaultLimits)
	closeErr := reader.Close()
	if err := errorsJoin(extractErr, closeErr); err != nil {
		return nil, nil, false, err
	}
	files := make([]pack.File, 0)
	var layerManifest []byte
	var hasLayerManifest bool
	err = fs.WalkDir(root.FS(), ".", func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if name == "." || entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("package layer path %q is not a regular file", name)
		}
		file, err := root.Open(filepath.ToSlash(name))
		if err != nil {
			return err
		}
		hash := sha256.New()
		writer := io.Writer(hash)
		var manifestBuffer bytes.Buffer
		if filepath.ToSlash(name) == canonical.FileName {
			hasLayerManifest = true
			if info.Size() > canonical.MaxSize {
				_ = file.Close()
				return fmt.Errorf("package-layer %s exceeds %d byte limit", canonical.FileName, canonical.MaxSize)
			}
			writer = io.MultiWriter(hash, &manifestBuffer)
		}
		size, copyErr := io.CopyBuffer(writer, file, make([]byte, 32<<10))
		fileCloseErr := file.Close()
		if err := errorsJoin(copyErr, fileCloseErr); err != nil {
			return err
		}
		mode := int64(0o644)
		if info.Mode().Perm()&0o111 != 0 {
			mode = 0o755
		}
		files = append(files, pack.File{Path: filepath.ToSlash(name), Size: size, SHA256: hex.EncodeToString(hash.Sum(nil)), Mode: mode})
		if filepath.ToSlash(name) == canonical.FileName {
			layerManifest = append([]byte(nil), manifestBuffer.Bytes()...)
		}
		return nil
	})
	if err != nil {
		return nil, nil, false, err
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	if err := pack.ValidateFileInventory(files); err != nil {
		return nil, nil, false, err
	}
	return files, layerManifest, hasLayerManifest, nil
}

func inventoryMismatch(expected, actual []pack.File) error {
	for i := 0; i < len(expected) && i < len(actual); i++ {
		if expected[i] != actual[i] {
			return fmt.Errorf("package layer inventory conflict at %q: config=%#v layer=%#v", expected[i].Path, expected[i], actual[i])
		}
	}
	return fmt.Errorf("package layer inventory file count conflicts: config=%d layer=%d", len(expected), len(actual))
}

func (r Repository) validateStoredArtifactLayer(rec Record) ([]byte, error) {
	config, err := r.readLimit("blobs/"+key(rec.ConfigDigest), 1<<20)
	if err != nil {
		return nil, err
	}
	var adversary []byte
	if rec.AdversaryManifestDigest != "" {
		adversary, err = r.readLimit("adversary-manifests/"+key(rec.AdversaryManifestDigest), 1<<20)
		if err != nil {
			return nil, err
		}
	}
	manifestData, err := r.readLimit("manifests/"+key(rec.ManifestDigest), 4<<20)
	if err != nil {
		return nil, err
	}
	var manifest oci.Manifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		return nil, err
	}
	layer, err := r.contentSource("blobs", rec.LayerDigest)
	if err != nil {
		return nil, err
	}
	return validateArtifactLayer(config, adversary, manifest.Annotations, layer)
}

func errorsJoin(errs ...error) error {
	return errors.Join(errs...)
}
