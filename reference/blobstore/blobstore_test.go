package blobstore

import "testing"

func TestPutGetVerified(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("warfarin data\n")
	h, err := s.Put(content)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Has(h) {
		t.Fatal("Has should be true after Put")
	}
	got, err := s.Get(h)
	if err != nil || string(got) != string(content) {
		t.Fatalf("Get mismatch: %q err=%v", got, err)
	}
	// PutVerified rejects content whose hash != expected (the verify-on-receipt guarantee)
	if err := s.PutVerified(h, []byte("tampered")); err == nil {
		t.Fatal("PutVerified must reject content that doesn't match the expected hash")
	}
}
