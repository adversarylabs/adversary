package blobsource

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
)

func TestSourceRepeatedIndependentOpens(t *testing.T) {
	src := Bytes([]byte("repeatable"))
	first, err := src.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	one := make([]byte, 3)
	if _, err := io.ReadFull(first, one); err != nil {
		t.Fatal(err)
	}
	second, err := src.Open()
	if err != nil {
		t.Fatal(err)
	}
	all, err := io.ReadAll(second)
	if err != nil {
		t.Fatal(err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	if string(one) != "rep" || string(all) != "repeatable" {
		t.Fatalf("independent reads: %q %q", one, all)
	}
}

func TestVerifyZeroAndLargeSourcesWithoutBuffering(t *testing.T) {
	if err := Verify(Bytes(nil)); err != nil {
		t.Fatal(err)
	}
	const size = int64(32 << 20)
	digest := "sha256:83ee47245398adee79bd9c0a8bc57b821e92aba10f5f9ade8a5d1fae4d8c4302"
	src, err := New(size, digest, func() (io.ReadCloser, error) {
		return io.NopCloser(io.LimitReader(zeroReader{}, size)), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(src); err != nil {
		t.Fatal(err)
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) { clear(p); return len(p), nil }

type errorReadCloser struct {
	io.Reader
	closeErr error
}

func (r errorReadCloser) Close() error { return r.closeErr }

func TestVerifyPreservesReadAndCloseErrors(t *testing.T) {
	readErr := errors.New("read failed")
	closeErr := errors.New("close failed")
	src, err := New(1, Bytes([]byte("x")).Digest(), func() (io.ReadCloser, error) {
		return errorReadCloser{Reader: io.MultiReader(strings.NewReader("x"), errorReader{readErr}), closeErr: closeErr}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	err = Verify(src)
	if !errors.Is(err, readErr) || !errors.Is(err, closeErr) {
		t.Fatalf("missing errors: %v", err)
	}
}

type errorReader struct{ err error }

func (r errorReader) Read([]byte) (int, error) { return 0, r.err }

func TestOwnedCleanupAndOpenAfterClose(t *testing.T) {
	cleaned := 0
	src := Owned(Bytes([]byte("owned")), func() error { cleaned++; return nil })
	reader, err := src.Open()
	if err != nil {
		t.Fatal(err)
	}
	if err := src.Close(); !errors.Is(err, ErrActiveReaders) {
		t.Fatalf("close with active reader = %v", err)
	}
	if cleaned != 0 {
		t.Fatalf("cleanup count %d", cleaned)
	}
	if _, err := src.Open(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("open error %v", err)
	}
	data, err := io.ReadAll(reader)
	if err != nil || !bytes.Equal(data, []byte("owned")) {
		t.Fatalf("existing reader: %q %v", data, err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if err := src.Close(); err != nil {
		t.Fatal(err)
	}
	if err := src.Close(); err != nil {
		t.Fatal(err)
	}
	if cleaned != 1 {
		t.Fatalf("cleanup count %d", cleaned)
	}
}

func TestVerifyRejectsOversizeAndEndlessSourcesBoundedly(t *testing.T) {
	for _, tc := range []struct {
		name   string
		size   int64
		reader func(*int) io.Reader
	}{
		{name: "oversize", size: 3, reader: func(read *int) io.Reader { return &countingReader{reader: strings.NewReader("four"), read: read} }},
		{name: "endless", size: 8, reader: func(read *int) io.Reader { return &countingReader{reader: zeroReader{}, read: read} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reads := 0
			src, err := New(tc.size, Bytes(make([]byte, tc.size)).Digest(), func() (io.ReadCloser, error) {
				return io.NopCloser(tc.reader(&reads)), nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := Verify(src); err == nil || !strings.Contains(err.Error(), "exceeds") {
				t.Fatalf("error = %v", err)
			}
			if reads > int(tc.size)+1 {
				t.Fatalf("read %d bytes for declared size %d", reads, tc.size)
			}
		})
	}
}

type countingReader struct {
	reader io.Reader
	read   *int
}

func (r *countingReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	*r.read += n
	return n, err
}

func TestVerifyMaxInt64DoesNotOverflowLimit(t *testing.T) {
	src, err := New(int64(^uint64(0)>>1), Bytes(nil).Digest(), func() (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader("")), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(src); err == nil || !strings.Contains(err.Error(), "size mismatch") {
		t.Fatalf("error = %v", err)
	}
}

func TestVerifyProbeToleratesTransientEmptyReadThenRejectsOverflow(t *testing.T) {
	reader := &stepReader{steps: []readStep{{data: "abc"}, {}, {data: "x"}, {err: io.EOF}}}
	src, err := New(3, Bytes([]byte("abc")).Digest(), func() (io.ReadCloser, error) { return io.NopCloser(reader), nil })
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(src); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("error = %v", err)
	}
}

func TestVerifyEmptyReaderTerminatesWithNoProgress(t *testing.T) {
	reads := 0
	src, err := New(1, Bytes([]byte("x")).Digest(), func() (io.ReadCloser, error) {
		return io.NopCloser(readerFunc(func([]byte) (int, error) { reads++; return 0, nil })), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(src); !errors.Is(err, io.ErrNoProgress) {
		t.Fatalf("error = %v", err)
	}
	if reads != maxConsecutiveEmptyReads {
		t.Fatalf("reads = %d", reads)
	}
}

type readStep struct {
	data string
	err  error
}
type stepReader struct{ steps []readStep }

func (r *stepReader) Read(p []byte) (int, error) {
	if len(r.steps) == 0 {
		return 0, io.EOF
	}
	step := r.steps[0]
	r.steps = r.steps[1:]
	return copy(p, step.data), step.err
}

type readerFunc func([]byte) (int, error)

func (f readerFunc) Read(p []byte) (int, error) { return f(p) }

func BenchmarkVerifyLargeSource(b *testing.B) {
	const size = int64(8 << 20)
	digest := "sha256:2daeb1f36095b44b318410b3f4e8b5d989dcc7bb023d1426c492dab0a3053e74"
	src, err := New(size, digest, func() (io.ReadCloser, error) {
		return io.NopCloser(io.LimitReader(zeroReader{}, size)), nil
	})
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.SetBytes(size)
	for i := 0; i < b.N; i++ {
		if err := Verify(src); err != nil {
			b.Fatal(err)
		}
	}
}
