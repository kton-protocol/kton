// Package oracle checks the kernel's OpenSSH key reader against golang.org/x/crypto/ssh
// (kton-review A4 on #277): whatever kton accepts, ssh accepts with the same seed. kton may refuse
// more (it reads Ed25519, aes256-ctr and bcrypt only, and checks more).
package oracle

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
	"kton.dev/plankton/keys"
)

const pass = "correct horse"

// rounds reads the bcrypt rounds of an OpenSSH key, 0 if there are none or the file is not one,
// so the fuzz target can skip inputs that would take seconds to decrypt.
func rounds(b []byte) uint32 {
	blk, _ := pem.Decode(b)
	if blk == nil {
		return 0
	}
	d := blk.Bytes
	const magic = "openssh-key-v1\x00"
	if !bytes.HasPrefix(d, []byte(magic)) {
		return 0
	}
	d = d[len(magic):]
	var opts []byte
	for i := 0; i < 3; i++ {
		if len(d) < 4 || uint64(binary.BigEndian.Uint32(d)) > uint64(len(d)-4) {
			return 0
		}
		n := binary.BigEndian.Uint32(d)
		opts, d = d[4:4+n], d[4+n:]
	}
	if len(opts) < 4 {
		return 0
	}
	return binary.BigEndian.Uint32(opts[len(opts)-4:])
}

func agree(t *testing.T, b []byte) {
	if !keys.IsPEM(b) {
		return // the plain hex seed is kton's own form; ssh has nothing to say about it
	}
	ours, err := keys.Parse(b, "", func(string) ([]byte, error) { return []byte(pass), nil })
	if err != nil {
		return
	}
	theirs, err := ssh.ParseRawPrivateKeyWithPassphrase(b, []byte(pass))
	if err != nil {
		// ssh refuses a passphrase for an unencrypted key; read it without one.
		theirs, err = ssh.ParseRawPrivateKey(b)
	}
	if err != nil {
		t.Fatalf("kton accepted a key x/crypto/ssh refuses: %v", err)
	}
	k, ok := theirs.(*ed25519.PrivateKey)
	if !ok || !bytes.Equal(*k, ours) {
		t.Fatalf("kton and x/crypto/ssh read different keys (%T)", theirs)
	}
}

func FuzzAgreesWithSSH(f *testing.F) {
	files, _ := filepath.Glob("../testdata/*.key")
	for _, p := range files {
		b, err := os.ReadFile(p)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	k := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{5}, 32))
	w, err := keys.MarshalEncrypted(k, []byte(pass))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(w)
	f.Fuzz(func(t *testing.T, b []byte) {
		if rounds(b) > 4 && len(b) != len(w) {
			// Too slow to fuzz; the seed corpus (rounds 1 to 64) still runs in full.
			return
		}
		agree(t, b)
	})
}

// What kton writes, ssh reads.
func TestSSHReadsWhatWeWrite(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	b, err := keys.MarshalEncrypted(priv, []byte(pass))
	if err != nil {
		t.Fatal(err)
	}
	theirs, err := ssh.ParseRawPrivateKeyWithPassphrase(b, []byte(pass))
	if err != nil {
		t.Fatal(err)
	}
	if k := theirs.(*ed25519.PrivateKey); !bytes.Equal(*k, priv) {
		t.Fatal("ssh read another key")
	}
}
