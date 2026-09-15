package core

import (
	"bytes"
	"fmt"
	"os"
)

// WriteKeyFile creates path holding exactly content, and REFUSES to overwrite an identity.
//
// `os.WriteFile(path, seed, 0600)` looks safe and is not, in two ways that both cost a key:
//
//   - The mode applies only when the call CREATES the file. An existing world-readable
//     `alice.key` keeps its 0644 and receives the new private seed. O_EXCL removes the case:
//     the file is always new, so the mode is the one this call asked for.
//   - `keygen alice` twice used to succeed twice. The old private seed is gone, and if the .pub
//     was the only retained copy of the public half, records signed with the old key can no
//     longer be checked against that filename. The signatures stay cryptographically valid;
//     what is destroyed is the ability to check them. (AUD-01)
//
// Three cases, in order:
//
//	identical content already there -> nothing to do. A deterministic `--seed` re-run is therefore
//	                                   idempotent, which is what a reproducible snapshot needs.
//	anything else already there     -> refuse, naming how to replace it on purpose. With force,
//	                                   the existing file is RENAMED to path+".old", never deleted:
//	                                   this function does not destroy key material, ever.
//	nothing there                   -> O_EXCL create at the requested mode.
//
// A failed write removes the partial file rather than leaving a truncated seed behind.
//
// The returned KeyWrite says what this call DID, which a caller needs in order to roll back safely.
// Without it a caller cannot tell "I created this file" from "it was already here holding exactly
// this key", and a keygen whose second half failed deleted a private key it had never written - with
// an error message promising the opposite protection (dev review R04).
type KeyWrite struct {
	Created bool   // this call created the file; nothing of the caller's was there before
	Backup  string // non-empty: --force renamed the previous file here; restore it to undo
}

// Undo reverses what this call did, and only what this call did. A file that was already there with
// the right content is left alone - it was not ours to remove.
func (w KeyWrite) Undo(path string) {
	if w.Backup != "" {
		os.Remove(path)
		os.Rename(w.Backup, path) // put the caller's original identity back exactly
		return
	}
	if w.Created {
		os.Remove(path)
	}
}

func WriteKeyFile(path string, content []byte, mode os.FileMode, force bool) (KeyWrite, error) {
	var w KeyWrite
	switch old, err := os.ReadFile(path); {
	case err == nil && bytes.Equal(old, content):
		return w, nil // already exactly this key - and NOT ours to undo
	case err == nil && !force:
		return w, fmt.Errorf("%s already exists and holds a DIFFERENT key - refusing to overwrite an identity.\n"+
			"  Overwriting would destroy the only copy of that private seed, and records signed with it\n"+
			"  could no longer be checked against this filename.\n"+
			"  To replace it deliberately: pass --force (which moves the existing file to %s.old),\n"+
			"  or move the file aside yourself.", path, path)
	case err == nil:
		if _, serr := os.Stat(path + ".old"); serr == nil {
			return w, fmt.Errorf("--force would move %s to %s.old, but that file already exists - move it\n"+
				"  away first; this command never deletes key material", path, path)
		}
		if rerr := os.Rename(path, path+".old"); rerr != nil {
			return w, rerr
		}
		w.Backup = path + ".old"
	case !os.IsNotExist(err):
		// An unreadable existing file is NOT an absent one. Falling through to "create it" here
		// would be the AUD-06 shape: a read failure silently becoming a fresh identity.
		return w, fmt.Errorf("cannot read the existing %s: %w", path, err)
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return w, err
	}
	w.Created = true
	if _, err := f.Write(content); err != nil {
		f.Close()
		os.Remove(path)
		w.Created = false
		return w, err
	}
	return w, f.Close()
}
