package registry

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// TestStoreFormat_ParallelCreate: writers creating a fresh store while others open it must never see
// the marker half-written. os.WriteFile creates the file empty and writes after, so a reader in
// between read "" and refused the store ("not readable"). Six `say` processes on a new repository hit
// exactly that (kton-cockpit, #251).
func TestStoreFormat_ParallelCreate(t *testing.T) {
	for round := 0; round < 200; round++ {
		objects := filepath.Join(t.TempDir(), "objects")
		if err := os.MkdirAll(objects, 0o755); err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		errs := make(chan error, 64)
		for w := 0; w < 4; w++ {
			wg.Add(2)
			go func() { defer wg.Done(); errs <- writeStoreFormat(objects) }()
			go func() {
				defer wg.Done()
				for i := 0; i < 20; i++ {
					if _, err := readStoreFormat(objects); err != nil {
						errs <- err
						return
					}
				}
			}()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatalf("round %d: %v", round, err)
			}
		}
		if v, err := readStoreFormat(objects); err != nil || v != StoreFormat {
			t.Fatalf("round %d: marker after the writers: %d, %v", round, v, err)
		}
	}
}
