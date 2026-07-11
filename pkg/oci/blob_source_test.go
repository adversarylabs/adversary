package oci

import (
	"io"
	"testing"
)

func TestBlobSourceAdapterIsRepeatable(t *testing.T) {
	data := []byte("content")
	blob := Blob{Descriptor: Descriptor{Digest: Digest(data), Size: int64(len(data))}, Data: data}
	stream, err := blob.Source()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		reader, err := stream.Source.Open()
		if err != nil {
			t.Fatal(err)
		}
		got, readErr := io.ReadAll(reader)
		closeErr := reader.Close()
		if readErr != nil || closeErr != nil || string(got) != string(data) {
			t.Fatalf("read %d: %q %v %v", i, got, readErr, closeErr)
		}
	}
}

func TestBlobSourceRejectsDescriptorConflict(t *testing.T) {
	data := []byte("content")
	blob := Blob{Descriptor: Descriptor{Digest: Digest(data), Size: 99}, Data: data}
	if _, err := blob.Source(); err == nil {
		t.Fatal("expected descriptor conflict")
	}
}
