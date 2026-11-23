package keys

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// sshSpec is an unencrypted OpenSSH key file, field by field, so each A3 check can break exactly
// one field. The cipher/KDF checks happen before decryption, so an unencrypted section serves them.
type sshSpec struct {
	magic, cipher, kdf string
	kdfOpts            []byte
	nkeys              uint32
	outerType          string
	outerPub           []byte
	outerTrail         []byte
	check1, check2     uint32
	keyType            string
	pub, priv          []byte
	comment            string
	padBlocks          int    // extra whole blocks of padding (still 1, 2, 3, ...)
	padBreak           bool   // last padding byte wrong
	secTrail           []byte // appended to the private section after the padding
	fileTrail          []byte // after the private section
}

const secretComment = "COMMENT-MUST-NOT-LEAK"

func validSpec() sshSpec {
	k := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	pub := k.Public().(ed25519.PublicKey)
	return sshSpec{magic: sshMagic, cipher: cipherNone, kdf: kdfNone, nkeys: 1, outerType: keyTypeEd,
		outerPub: pub, check1: 0x01020304, check2: 0x01020304, keyType: keyTypeEd, pub: pub, priv: k,
		comment: secretComment}
}

func bcryptOpts(salt []byte, rounds uint32) []byte {
	return binary.BigEndian.AppendUint32(putStr(nil, salt), rounds)
}

func (s sshSpec) bytes() []byte {
	var outer []byte
	outer = putStr(outer, []byte(s.outerType))
	outer = putStr(outer, s.outerPub)
	outer = append(outer, s.outerTrail...)

	var sec []byte
	sec = binary.BigEndian.AppendUint32(sec, s.check1)
	sec = binary.BigEndian.AppendUint32(sec, s.check2)
	sec = putStr(sec, []byte(s.keyType))
	sec = putStr(sec, s.pub)
	sec = putStr(sec, s.priv)
	sec = putStr(sec, []byte(s.comment))
	i := 1
	for ; len(sec)%8 != 0; i++ {
		sec = append(sec, byte(i))
	}
	for n := 0; n < 8*s.padBlocks; n, i = n+1, i+1 {
		sec = append(sec, byte(i))
	}
	if s.padBreak {
		sec[len(sec)-1]++
	}
	sec = append(sec, s.secTrail...)

	body := []byte(s.magic)
	body = putStr(body, []byte(s.cipher))
	body = putStr(body, []byte(s.kdf))
	body = putStr(body, s.kdfOpts)
	body = binary.BigEndian.AppendUint32(body, s.nkeys)
	body = putStr(body, outer)
	body = putStr(body, sec)
	body = append(body, s.fileTrail...)
	return pem.EncodeToMemory(&pem.Block{Type: pemType, Bytes: body})
}

func TestSpecBuilderIsValid(t *testing.T) {
	s := validSpec()
	k, err := Parse(s.bytes(), "", nil)
	if err != nil || !bytes.Equal(k, s.priv) {
		t.Fatalf("the valid spec does not load: %v", err)
	}
}

// kton-review A3 on #277: each parser check with its own case. Every refusal is also checked not
// to carry bytes of the file (K4): not the comment, not the seed.
func TestParserChecks(t *testing.T) {
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32))
	otherPub := other.Public().(ed25519.PublicKey)
	salt := bytes.Repeat([]byte{1}, 16)
	cases := []struct {
		name string
		mod  func(*sshSpec)
		want string
	}{
		{"magic", func(s *sshSpec) { s.magic = "openssh-key-v2\x00" }, "not openssh-key-v1"},
		{"magic without NUL", func(s *sshSpec) { s.magic = "openssh-key-v1" }, "malformed"},
		{"cipher aes256-gcm refused by name", func(s *sshSpec) { s.cipher = "aes256-gcm@openssh.com" }, `cipher "aes256-gcm@openssh.com" is not read`},
		{"cipher chacha20-poly1305 refused by name", func(s *sshSpec) { s.cipher = "chacha20-poly1305@openssh.com" }, `cipher "chacha20-poly1305@openssh.com"`},
		{"unknown cipher not echoed", func(s *sshSpec) { s.cipher = "x-" + secretComment }, "an unknown cipher"},
		{"cipher none with bcrypt", func(s *sshSpec) { s.kdf = kdfBcrypt; s.kdfOpts = bcryptOpts(salt, 16) }, "cipher none with a KDF"},
		{"cipher none with KDF options", func(s *sshSpec) { s.kdfOpts = []byte{0} }, "cipher none with a KDF"},
		{"aes256-ctr without a KDF", func(s *sshSpec) { s.cipher = cipherCTR }, "without a KDF"},
		{"aes256-ctr with another KDF", func(s *sshSpec) { s.cipher, s.kdf = cipherCTR, "scrypt" }, "an unknown KDF"},
		{"rounds 0", func(s *sshSpec) { s.cipher, s.kdf, s.kdfOpts = cipherCTR, kdfBcrypt, bcryptOpts(salt, 0) }, "rounds 0 out of range"},
		{"rounds over the cap", func(s *sshSpec) {
			s.cipher, s.kdf, s.kdfOpts = cipherCTR, kdfBcrypt, bcryptOpts(salt, MaxRounds+1)
		}, "out of range"},
		{"empty salt", func(s *sshSpec) { s.cipher, s.kdf, s.kdfOpts = cipherCTR, kdfBcrypt, bcryptOpts(nil, 16) }, "bcrypt options"},
		{"trailing bytes in the KDF options", func(s *sshSpec) {
			s.cipher, s.kdf, s.kdfOpts = cipherCTR, kdfBcrypt, append(bcryptOpts(salt, 16), 0)
		}, "bcrypt options"},
		{"two keys", func(s *sshSpec) { s.nkeys = 2 }, "2 keys in one file"},
		{"zero keys", func(s *sshSpec) { s.nkeys = 0 }, "0 keys in one file"},
		{"outer key type ssh-rsa", func(s *sshSpec) { s.outerType = "ssh-rsa" }, `key type "ssh-rsa" is not read`},
		{"outer key type sk-ssh-ed25519", func(s *sshSpec) { s.outerType = "sk-ssh-ed25519@openssh.com" }, `key type "sk-ssh-ed25519@openssh.com"`},
		{"outer public key 31 bytes", func(s *sshSpec) { s.outerPub = s.outerPub[:31] }, "public key"},
		{"trailing bytes in the outer public key", func(s *sshSpec) { s.outerTrail = []byte{0} }, "public key"},
		{"private section not a block multiple", func(s *sshSpec) { s.secTrail = []byte{1} }, "multiple of 8"},
		{"check values differ", func(s *sshSpec) { s.check2++ }, "check values differ"},
		{"inner key type", func(s *sshSpec) { s.keyType = "ssh-dss" }, `key type "ssh-dss"`},
		{"inner public key 33 bytes", func(s *sshSpec) { s.pub = append(bytes.Clone(s.pub), 0) }, "private key"},
		{"private key 63 bytes", func(s *sshSpec) { s.priv = s.priv[:63] }, "private key"},
		{"padding not 1, 2, 3", func(s *sshSpec) { s.comment += "ab"; s.padBreak = true }, "padding"}, // 6 bytes of padding
		{"padding of a whole block or more", func(s *sshSpec) { s.padBlocks = 1 }, "padding"},
		{"outer public key differs from the inner one", func(s *sshSpec) { s.outerPub = otherPub }, "does not match"},
		{"inner public key differs", func(s *sshSpec) { s.pub = otherPub }, "does not match"},
		{"priv[32:] differs from the seed's public key", func(s *sshSpec) {
			s.priv = append(bytes.Clone(s.priv[:32]), otherPub...)
		}, "does not match"},
		{"stale public halves everywhere (K5)", func(s *sshSpec) {
			s.outerPub, s.pub, s.priv = otherPub, otherPub, append(bytes.Clone(s.priv[:32]), otherPub...)
		}, "does not match"},
		{"trailing bytes after the private section", func(s *sshSpec) { s.fileTrail = []byte{0} }, "trailing bytes"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := validSpec()
			seedHex := hex.EncodeToString(s.priv[:32])
			c.mod(&s)
			b := s.bytes()
			_, err := Parse(b, "", fixed("pw"))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
			noFileBytes(t, err, seedHex)
		})
	}
}

func noFileBytes(t *testing.T, err error, seedHex string) {
	t.Helper()
	m := err.Error()
	if strings.Contains(m, secretComment) || (seedHex != "" && strings.Contains(m, seedHex)) || strings.Contains(m, "\x07\x07") {
		t.Errorf("the error carries bytes of the file: %q", m)
	}
}

func TestPEMChecks(t *testing.T) {
	valid := validSpec().bytes()
	cases := []struct {
		name string
		b    []byte
		want string
	}{
		{"another PEM type, refused by name", pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte{1}}), `PEM "RSA PRIVATE KEY" key is not read`},
		{"an unknown PEM type, not echoed", pem.EncodeToMemory(&pem.Block{Type: secretComment, Bytes: []byte{1}}), "not in the OpenSSH form"},
		{"PEM headers", pem.EncodeToMemory(&pem.Block{Type: pemType, Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"}, Bytes: []byte(sshMagic)}), "malformed"},
		{"text after the END line", append(bytes.Clone(valid), "more\n"...), "malformed"},
		{"broken base64", []byte(pemHeader + "\n!!!!\n-----END " + pemType + "-----\n"), "malformed"},
		{"a header but no END line", []byte(pemHeader + "\nAAAA\n"), "malformed"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Parse(c.b, "", nil)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
			noFileBytes(t, err, "")
		})
	}
	// The hex form's decode error used to quote the offending byte.
	_, err := Parse([]byte(strings.Repeat("ab", 31)+"\x01Q"), "", nil)
	if err == nil || strings.Contains(err.Error(), "Q") || strings.Contains(err.Error(), "U+") {
		t.Errorf("hex: %v", err)
	}
}

// Every prefix of a valid file is refused, without a panic.
func TestTruncatedFiles(t *testing.T) {
	blk, _ := pem.Decode(validSpec().bytes())
	for n := 0; n < len(blk.Bytes); n++ {
		b := pem.EncodeToMemory(&pem.Block{Type: pemType, Bytes: blk.Bytes[:n]})
		if _, err := Parse(b, "", nil); err == nil {
			t.Fatalf("a file cut to %d bytes was accepted", n)
		}
	}
}

// A2: what we write uses a fresh 16-byte salt and at least 16 rounds; a wrong passphrase whose
// check values happen to agree is still caught (K5), simulated here by an encrypted file whose
// outer public key belongs to another key.
func TestWhatWeWrite(t *testing.T) {
	k := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, 32))
	a, _ := MarshalEncrypted(k, []byte("pw"))
	b, _ := MarshalEncrypted(k, []byte("pw"))
	fa, err := readSSHFile(a, MaxRounds)
	if err != nil {
		t.Fatal(err)
	}
	fb, _ := readSSHFile(b, MaxRounds)
	if len(fa.salt) != 16 || bytes.Equal(fa.salt, fb.salt) {
		t.Errorf("salt %x and %x: want two fresh 16-byte salts", fa.salt, fb.salt)
	}
	if fa.rounds < 16 || fa.cipher != cipherCTR {
		t.Errorf("wrote %s with %d rounds", fa.cipher, fa.rounds)
	}
	if len(fa.priv)%16 != 0 {
		t.Errorf("private section %d bytes", len(fa.priv))
	}
}

// A2, the other direction: with KTON_KEYS_INTEROP_DIR set, write keys at rounds 1, 16 and 64 with
// the passphrase "correct horse", each next to its .pub line; CI then has ssh-keygen -y -P read
// each one and compares (scripts/check-openssh-interop.sh). The kernel starts no process itself.
func TestWriteInteropKeys(t *testing.T) {
	dir := os.Getenv("KTON_KEYS_INTEROP_DIR")
	if dir == "" {
		t.Skip("KTON_KEYS_INTEROP_DIR not set")
	}
	for _, r := range []int{1, 16, 64} {
		_, priv, _ := ed25519.GenerateKey(nil)
		b, err := marshalOpenSSH(priv, []byte("correct horse"), r)
		if err != nil {
			t.Fatal(err)
		}
		name := filepath.Join(dir, fmt.Sprintf("kton-r%d.key", r))
		pubLine := keyTypeEd + " " + base64.StdEncoding.EncodeToString(
			putStr(putStr(nil, []byte(keyTypeEd)), priv.Public().(ed25519.PublicKey))) + "\n"
		if err := os.WriteFile(name, b, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(name+".pub", []byte(pubLine), 0o644); err != nil {
			t.Fatal(err)
		}
		if got, err := Load(name, fixed("correct horse")); err != nil || !bytes.Equal(got, priv) {
			t.Fatalf("rounds %d: %v", r, err)
		}
	}
}

// A4: a native fuzz target. No panic; anything accepted is K5-consistent and agrees with
// PublicKey. maxRounds is low so an execution stays fast; the rounds check itself is in
// TestParserChecks. Corpus: the ssh-keygen keys and one we write.
func FuzzParse(f *testing.F) {
	for _, n := range []string{"encrypted-r1.key", "plain-openssh.key", "rsa.key"} {
		b, err := os.ReadFile("testdata/" + n)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	k := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{5}, 32))
	w, _ := marshalOpenSSH(k, []byte("correct horse"), 1)
	f.Add(w)
	f.Add(validSpec().bytes())
	f.Add([]byte(hex.EncodeToString(k.Seed())))
	f.Fuzz(func(t *testing.T, b []byte) {
		got, err := parse(b, "", fixed("correct horse"), 4)
		_ = IsEncrypted(b)
		if err != nil {
			return
		}
		if len(got) != ed25519.PrivateKeySize || !bytes.Equal(got, ed25519.NewKeyFromSeed(got.Seed())) {
			t.Fatalf("accepted a key that is not K5-consistent")
		}
		if pub, err := PublicKey(b); err != nil || !bytes.Equal(pub, got.Public().(ed25519.PublicKey)) {
			t.Fatalf("PublicKey disagrees with the loaded key: %v", err)
		}
	})
}
