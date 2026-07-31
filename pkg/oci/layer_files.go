package oci

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"path"
	"strings"

	"github.com/adversarylabs/adversary/pkg/blobsource"
)

// ExtractLayerFiles returns the named files from an adversary package layer
// (tar+gzip). Missing names are omitted from the result.
func ExtractLayerFiles(layer blobsource.Source, names ...string) (map[string][]byte, error) {
	if layer == nil {
		return nil, fmt.Errorf("package layer is nil")
	}
	want := make(map[string]struct{}, len(names))
	for _, name := range names {
		clean := path.Clean("/" + strings.TrimPrefix(filepathToSlash(name), "/"))
		clean = strings.TrimPrefix(clean, "/")
		if clean == "" || clean == "." {
			continue
		}
		want[clean] = struct{}{}
	}
	if len(want) == 0 {
		return map[string][]byte{}, nil
	}

	r, err := layer.Open()
	if err != nil {
		return nil, err
	}
	defer r.Close()

	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("open package layer gzip: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	out := make(map[string][]byte, len(want))
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read package layer tar: %w", err)
		}
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
			continue
		}
		name := path.Clean("/" + strings.TrimPrefix(filepathToSlash(header.Name), "/"))
		name = strings.TrimPrefix(name, "/")
		if _, ok := want[name]; !ok {
			continue
		}
		// Bound individual doc files (2 MiB).
		const maxDoc = 2 << 20
		if header.Size > maxDoc {
			return nil, fmt.Errorf("layer file %q exceeds %d bytes", name, maxDoc)
		}
		data, err := io.ReadAll(io.LimitReader(tr, maxDoc+1))
		if err != nil {
			return nil, fmt.Errorf("read layer file %q: %w", name, err)
		}
		if int64(len(data)) > maxDoc {
			return nil, fmt.Errorf("layer file %q exceeds %d bytes", name, maxDoc)
		}
		out[name] = data
		if len(out) == len(want) {
			break
		}
	}
	return out, nil
}

func filepathToSlash(p string) string {
	return strings.ReplaceAll(p, "\\", "/")
}
