package registry

// material.go implements SPEC §8.1 for plankton: external evidence ABOUT a foton - who signed it,
// or that it existed by a given time - bound to the foton by its content address.
//
// The kernel NEVER interprets Material. It is opaque bytes produced by some other scheme, and
// deciding which issuers count is a consumer concern: the same split as trust policy (§8), for the
// same reason - whose word counts is not a property of the record.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// VerificationMaterial is evidence about a record, bound by the record's content address (§8.1).
type VerificationMaterial struct {
	Subject   string `json:"subject"`   // the record's content address - here, a foton id
	Scheme    string `json:"scheme"`    // what produced Material; an UNKNOWN scheme is carried, never rejected
	MediaType string `json:"mediaType"` // how to read Material
	Material  string `json:"material"`  // base64 of the scheme's own artifact
}

// materialPath: plankton's store has no scope axis (nekton splits by subnekton, §7.4), so this is
// one file for the registry rather than one per scope.
func materialPath(objectsDir string) string {
	return filepath.Join(objectsDir, "material.jsonl")
}

// withMaterialLock serializes appends to the material file across processes.
func (r *Registry) withMaterialLock(fn func() error) error {
	return r.withLock(".material.lock", fn)
}

// withLock serializes a read-modify-write across INDEPENDENT PROCESSES, per named lock file.
//
// Named rather than store-wide on purpose: a lock is only worth taking where two writers can
// actually reach the same file. plankton writes exactly three kinds of file - one object per
// record, one peers.json, one material.jsonl - so contention is per object, plus one for each of
// the other two. A single store-wide lock would serialize a bulk ingest that has no conflict in it.
func (r *Registry) withLock(name string, fn func() error) error {
	lp := filepath.Join(r.dir, name)
	for attempt := 0; attempt < 2000; attempt++ {
		f, err := os.OpenFile(lp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
		if err == nil {
			f.Close()
			defer os.Remove(lp)
			return fn()
		}
		if !os.IsExist(err) {
			return err
		}
		if fi, e := os.Stat(lp); e == nil && time.Since(fi.ModTime()) > 30*time.Second {
			os.Remove(lp) // steal a stale lock (crashed holder)
			continue
		}
		time.Sleep(5 * time.Millisecond)
	}
	return fmt.Errorf("could not acquire the material write lock (%s)", lp)
}

// readMaterial parses the material file. Tolerant on purpose: one corrupt line must not hide the
// rest, and must never affect the records the file is about (§8.1, §11).
func readMaterial(objectsDir string) map[string][]VerificationMaterial {
	out := map[string][]VerificationMaterial{}
	f, err := os.Open(materialPath(objectsDir))
	if err != nil {
		return out
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var vm VerificationMaterial
		if err := json.Unmarshal([]byte(line), &vm); err != nil || vm.Subject == "" {
			fmt.Fprintf(os.Stderr, "warning: skipping unreadable verification material in %s\n", materialPath(objectsDir))
			continue
		}
		out[vm.Subject] = append(out[vm.Subject], vm)
	}
	return out
}

// Material returns the evidence recorded about a subject, in attachment order. The kernel evaluates
// none of it (§8.1, §15).
func (r *Registry) Material(subject string) []VerificationMaterial { return r.material[subject] }

// AttachMaterial records evidence about a foton already in this registry.
//
// The subject MUST be a foton id, not the hash of the envelope payload. For a nekton claim those
// coincide - a claim id IS sha256(canon(Statement)) - but a FOTON id is computed over the covered
// projection (§6.3), which excludes carried uri/id/mediaType. So a Rekor entry about a foton
// commits to the payload hash while `subject` names the foton id, and the binding is one hop
// rather than direct: subject -> the stored envelope -> its payload -> sha256 -> the entry's
// payloadHash. Everything that check needs is already on disk.
//
// It deliberately does NOT verify Material, and does not care whether Scheme is one it has heard
// of: refusing unknown evidence would make the set of schemes a protocol version, which is
// precisely what §8.1 exists to avoid.
func (r *Registry) AttachMaterial(vm VerificationMaterial) error {
	if vm.Subject == "" || vm.Scheme == "" || vm.Material == "" {
		return fmt.Errorf("verification material needs subject, scheme and material")
	}
	if _, ok := r.foton[vm.Subject]; !ok {
		return fmt.Errorf("no foton %s in this registry - material binds to a record's content address, not to a file", vm.Subject)
	}
	path := materialPath(r.objectsDir)
	err := r.withMaterialLock(func() error {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		b, err := json.Marshal(vm)
		if err != nil {
			return err
		}
		f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = f.Write(append(b, '\n'))
		return err
	})
	if err != nil {
		return err
	}
	r.material[vm.Subject] = append(r.material[vm.Subject], vm)
	return nil
}
