// Package blobsource defines repeatable, bounded-memory artifact content.
package blobsource

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	digestapi "github.com/opencontainers/go-digest"
)

// ErrActiveReaders means cleanup was requested while readers still own the
// backing content. Close those readers and retry Close.
var ErrActiveReaders = errors.New("blob source has active readers")

// Source describes immutable content. Each successful Open returns an
// independent reader positioned at byte zero; the caller owns that reader.
// Implementations must return exactly Size bytes whose digest is Digest.
type Source interface {
	Size() int64
	Digest() string
	Open() (io.ReadCloser, error)
}

type source struct {
	size   int64
	digest string
	open   func() (io.ReadCloser, error)
}

// New creates a repeatable source. It does not open or buffer the content.
func New(size int64, digest string, open func() (io.ReadCloser, error)) (Source, error) {
	if size < 0 {
		return nil, fmt.Errorf("blob size must be non-negative")
	}
	if _, err := parseDigest(digest); err != nil {
		return nil, err
	}
	if open == nil {
		return nil, fmt.Errorf("blob open function is required")
	}
	return &source{size: size, digest: digest, open: open}, nil
}

func (s *source) Size() int64                  { return s.size }
func (s *source) Digest() string               { return s.digest }
func (s *source) Open() (io.ReadCloser, error) { return s.open() }

// Bytes adapts byte content. It computes the identity once and returns
// independent readers without copying; the caller must not mutate data.
func Bytes(data []byte) Source {
	digest := digestapi.SHA256.FromBytes(data).String()
	return &source{size: int64(len(data)), digest: digest, open: func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(data)), nil
	}}
}

// File adapts a caller-owned immutable file. The path is reopened for every
// read; callers must keep it present and unchanged for the Source lifetime.
func File(path, digest string) (Source, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("blob source %q is not a regular file", path)
	}
	return New(info.Size(), digest, func() (io.ReadCloser, error) { return os.Open(path) })
}

// Owned gives a Source an explicit cleanup lifecycle, for example for a
// downloaded temporary file. Close is idempotent, prevents future opens, and
// does not close readers that callers already own.
func Owned(src Source, cleanup func() error) SourceCloser {
	return &owned{Source: src, cleanup: cleanup}
}

// SourceCloser is a Source whose backing resources require explicit release.
type SourceCloser interface {
	Source
	io.Closer
}

type owned struct {
	Source
	mu       sync.Mutex
	closing  bool
	closed   bool
	active   int
	closeErr error
	cleanup  func() error
}

func (s *owned) Open() (io.ReadCloser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing || s.closed {
		return nil, os.ErrClosed
	}
	reader, err := s.Source.Open()
	if err != nil {
		return nil, err
	}
	s.active++
	return &trackedReader{ReadCloser: reader, release: func() {
		s.mu.Lock()
		s.active--
		s.mu.Unlock()
	}}, nil
}

func (s *owned) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return s.closeErr
	}
	s.closing = true
	if s.active != 0 {
		return ErrActiveReaders
	}
	if s.cleanup != nil {
		s.closeErr = s.cleanup()
	}
	if s.closeErr == nil {
		s.closed = true
	}
	return s.closeErr
}

type trackedReader struct {
	io.ReadCloser
	once    sync.Once
	release func()
}

func (r *trackedReader) Close() error {
	err := r.ReadCloser.Close()
	r.once.Do(r.release)
	return err
}

// Verify streams a source once and checks its declared size and digest. Read
// and Close failures are both preserved. It never buffers the content.
func Verify(src Source) error {
	if src == nil {
		return fmt.Errorf("nil blob source")
	}
	digest, err := parseDigest(src.Digest())
	if err != nil {
		return err
	}
	reader, err := src.Open()
	if err != nil {
		return err
	}
	hash := digest.Algorithm().Digester()
	n, overflow, readErr := copyExactAndProbe(hash.Hash(), reader, src.Size())
	if readErr == io.EOF && n != src.Size() {
		readErr = fmt.Errorf("blob size mismatch: read %d, expected %d", n, src.Size())
	}
	if overflow {
		overflowErr := fmt.Errorf("blob size exceeds declared %d bytes", src.Size())
		readErr = errors.Join(overflowErr, readErr)
	} else if readErr == io.EOF && n == src.Size() {
		readErr = nil
	}
	closeErr := reader.Close()
	if readErr == nil && hash.Digest() != digest {
		readErr = fmt.Errorf("blob digest mismatch for %s", digest)
	}
	return errors.Join(readErr, closeErr)
}

const maxConsecutiveEmptyReads = 100

// copyExactAndProbe copies exactly size bytes and then proves EOF with a
// one-byte probe. It bounds readers that repeatedly return (0, nil).
func copyExactAndProbe(dst io.Writer, src io.Reader, size int64) (written int64, overflow bool, err error) {
	buffer := make([]byte, 32<<10)
	emptyReads := 0
	for written < size {
		want := int64(len(buffer))
		if remaining := size - written; remaining < want {
			want = remaining
		}
		n, readErr := src.Read(buffer[:int(want)])
		if n < 0 || n > int(want) {
			return written, false, fmt.Errorf("blob reader returned invalid byte count %d", n)
		}
		if n > 0 {
			emptyReads = 0
			writeN, writeErr := dst.Write(buffer[:n])
			written += int64(writeN)
			if writeErr != nil {
				return written, false, errors.Join(writeErr, readErr)
			}
			if writeN != n {
				return written, false, errors.Join(io.ErrShortWrite, readErr)
			}
		} else if readErr == nil {
			emptyReads++
			if emptyReads >= maxConsecutiveEmptyReads {
				return written, false, io.ErrNoProgress
			}
		}
		if readErr != nil {
			return written, false, readErr
		}
	}
	var probe [1]byte
	for {
		n, readErr := src.Read(probe[:])
		if n > 0 {
			return written, true, readErr
		}
		if readErr != nil {
			return written, false, readErr
		}
		emptyReads++
		if emptyReads >= maxConsecutiveEmptyReads {
			return written, false, io.ErrNoProgress
		}
	}
}

func parseDigest(value string) (digestapi.Digest, error) {
	digest, err := digestapi.Parse(value)
	if err != nil || digest.Validate() != nil || !digest.Algorithm().Available() {
		return "", fmt.Errorf("invalid or unsupported blob digest %q", value)
	}
	return digest, nil
}
