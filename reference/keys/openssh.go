package keys

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"

	"kton.dev/plankton/keys/internal/bcrypt_pbkdf"
)

// The OpenSSH private-key format ("openssh-key-v1", PROTOCOL.key in the OpenSSH sources), read and
// written for Ed25519 only. golang.org/x/crypto/ssh reads it too, but brings the whole SSH protocol
// with it; this file needs only bcrypt_pbkdf (copied from x/crypto, see internal/bcrypt_pbkdf) and
// the standard library's AES-CTR (MH 23.11. on #277; kton-review A1-A5).
//
// The checks follow kton-review A3 on #277, in the order the bytes are read. Nothing is allocated
// from a length field: every string is a slice of the input, bounds-checked before it is taken.

const (
	pemType     = "OPENSSH PRIVATE KEY"
	pemHeader   = "-----BEGIN " + pemType + "-----"
	sshMagic    = "openssh-key-v1\x00"
	keyTypeEd   = "ssh-ed25519"
	cipherNone  = "none"
	cipherCTR   = "aes256-ctr"
	kdfNone     = "none"
	kdfBcrypt   = "bcrypt"
	saltLen     = 16 // what ssh-keygen writes; a fresh random salt per write (A2)
	maxSaltLen  = 1024
	writeRounds = 24 // ssh-keygen's default (OpenSSH 9.6); kton-review A2: at least 16 when we write

	// MaxRounds is the largest bcrypt_pbkdf rounds value read. Each round costs a few ms, so the
	// cap bounds how long a key file can make the loader work; ssh-keygen's default is 24.
	MaxRounds = 1024
)

// Names a refusal may give. Only these are echoed; any other cipher, KDF or key type in a file is
// refused without repeating it, so an error never carries bytes from the file (K4).
var knownNames = map[string]bool{
	"aes128-ctr": true, "aes192-ctr": true, "aes128-cbc": true, "aes192-cbc": true, "aes256-cbc": true,
	"3des-cbc": true, "aes128-gcm@openssh.com": true, "aes256-gcm@openssh.com": true,
	"chacha20-poly1305@openssh.com": true,
	"ssh-rsa":                       true, "ssh-dss": true, "ecdsa-sha2-nistp256": true, "ecdsa-sha2-nistp384": true,
	"ecdsa-sha2-nistp521": true, "sk-ssh-ed25519@openssh.com": true, "sk-ecdsa-sha2-nistp256@openssh.com": true,
}

func named(what string, b []byte) string {
	if knownNames[string(b)] {
		return fmt.Sprintf("%s %q", what, b)
	}
	return "an unknown " + what
}

var errMalformed = errors.New("malformed OpenSSH private key")

// sshFile is an OpenSSH key file with its outer layer read; priv is still encrypted when cipher is
// aes256-ctr.
type sshFile struct {
	cipher string
	salt   []byte
	rounds int
	pub    ed25519.PublicKey
	priv   []byte
}

func (f *sshFile) encrypted() bool { return f.cipher != cipherNone }

func (f *sshFile) blockSize() int {
	if f.encrypted() {
		return aes.BlockSize
	}
	return 8 // the "none" cipher's block size in OpenSSH (cipher.c)
}

type sshReader struct{ b []byte }

func (r *sshReader) u32() (uint32, bool) {
	if len(r.b) < 4 {
		return 0, false
	}
	v := binary.BigEndian.Uint32(r.b)
	r.b = r.b[4:]
	return v, true
}

func (r *sshReader) str() ([]byte, bool) {
	n, ok := r.u32()
	if !ok || uint64(n) > uint64(len(r.b)) {
		return nil, false
	}
	s := r.b[:n:n]
	r.b = r.b[n:]
	return s, true
}

// decodePEM checks the exact header and returns the binary body. Any other PEM is refused by name.
func decodePEM(b []byte) ([]byte, error) {
	t := bytes.TrimSpace(b)
	blk, rest := pem.Decode(t)
	if blk == nil {
		if bytes.HasPrefix(t, []byte(pemHeader)) {
			return nil, errMalformed
		}
		return nil, errors.New("not a PEM key")
	}
	if blk.Type != pemType {
		known := map[string]bool{"RSA PRIVATE KEY": true, "EC PRIVATE KEY": true, "DSA PRIVATE KEY": true,
			"PRIVATE KEY": true, "ENCRYPTED PRIVATE KEY": true, "PUBLIC KEY": true}
		if known[blk.Type] {
			return nil, fmt.Errorf("a PEM %q key is not read: kton reads the OpenSSH form "+
				"(ssh-keygen -t ed25519) or the plain hex seed", blk.Type)
		}
		return nil, errors.New("a PEM key that is not in the OpenSSH form is not read")
	}
	if !bytes.HasPrefix(t, []byte(pemHeader)) || len(blk.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errMalformed
	}
	return blk.Bytes, nil
}

// readSSHFile reads the outer, unencrypted layer: magic, cipher, KDF, the one public key, and the
// private section, which is not looked into here.
func readSSHFile(b []byte, maxRounds int) (*sshFile, error) {
	body, err := decodePEM(b)
	if err != nil {
		return nil, err
	}
	if !bytes.HasPrefix(body, []byte(sshMagic)) {
		return nil, fmt.Errorf("%w: not openssh-key-v1", errMalformed)
	}
	r := &sshReader{body[len(sshMagic):]}
	cipherName, ok1 := r.str()
	kdfName, ok2 := r.str()
	kdfOpts, ok3 := r.str()
	if !ok1 || !ok2 || !ok3 {
		return nil, errMalformed
	}
	f := &sshFile{cipher: string(cipherName)}
	switch f.cipher {
	case cipherNone:
		if string(kdfName) != kdfNone || len(kdfOpts) != 0 {
			return nil, fmt.Errorf("%w: cipher none with a KDF", errMalformed)
		}
	case cipherCTR:
		if string(kdfName) != kdfBcrypt {
			if string(kdfName) == kdfNone {
				return nil, fmt.Errorf("%w: cipher %s without a KDF", errMalformed, cipherCTR)
			}
			return nil, fmt.Errorf("%s is not read; the KDF must be bcrypt", named("KDF", kdfName))
		}
		o := &sshReader{kdfOpts}
		salt, ok := o.str()
		rounds, ok2 := o.u32()
		if !ok || !ok2 || len(o.b) != 0 || len(salt) == 0 || len(salt) > maxSaltLen {
			return nil, fmt.Errorf("%w: bcrypt options", errMalformed)
		}
		if rounds < 1 || uint64(rounds) > uint64(maxRounds) {
			return nil, fmt.Errorf("bcrypt rounds %d out of range 1..%d", rounds, maxRounds)
		}
		f.salt, f.rounds = salt, int(rounds)
	default:
		return nil, fmt.Errorf("%s is not read; kton reads %s and %s", named("cipher", cipherName), cipherNone, cipherCTR)
	}
	n, ok := r.u32()
	if !ok {
		return nil, errMalformed
	}
	if n != 1 {
		return nil, fmt.Errorf("%w: %d keys in one file, want 1", errMalformed, n)
	}
	pubBlob, ok := r.str()
	if !ok {
		return nil, errMalformed
	}
	if f.pub, err = readEdPublic(pubBlob); err != nil {
		return nil, err
	}
	if f.priv, ok = r.str(); !ok || len(r.b) != 0 {
		return nil, fmt.Errorf("%w: private section or trailing bytes", errMalformed)
	}
	if len(f.priv) == 0 || len(f.priv)%f.blockSize() != 0 {
		return nil, fmt.Errorf("%w: private section is not a multiple of %d bytes", errMalformed, f.blockSize())
	}
	return f, nil
}

func readEdPublic(blob []byte) (ed25519.PublicKey, error) {
	r := &sshReader{blob}
	kt, ok := r.str()
	if !ok {
		return nil, errMalformed
	}
	if string(kt) != keyTypeEd {
		return nil, fmt.Errorf("%s is not read; kton signs with Ed25519 only", named("key type", kt))
	}
	pub, ok := r.str()
	if !ok || len(pub) != ed25519.PublicKeySize || len(r.b) != 0 {
		return nil, fmt.Errorf("%w: public key", errMalformed)
	}
	return ed25519.PublicKey(bytes.Clone(pub)), nil
}

// open decrypts (if needed) and reads the private section. pass is used only when the file is
// encrypted. The decrypted buffer and the derived key are zeroed before it returns.
func (f *sshFile) open(pass []byte) (ed25519.PrivateKey, error) {
	sec := bytes.Clone(f.priv)
	defer clear(sec)
	if f.encrypted() {
		if len(pass) == 0 {
			return nil, ErrWrongPassphrase
		}
		k, err := bcrypt_pbkdf.Key(pass, f.salt, f.rounds, 32+aes.BlockSize)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", errMalformed, err)
		}
		defer clear(k)
		blk, err := aes.NewCipher(k[:32])
		if err != nil {
			return nil, err
		}
		cipher.NewCTR(blk, k[32:]).XORKeyStream(sec, sec)
	}
	r := &sshReader{sec}
	c1, ok1 := r.u32()
	c2, ok2 := r.u32()
	if !ok1 || !ok2 {
		return nil, errMalformed
	}
	if c1 != c2 {
		// 32 bits only: a wrong passphrase passes this 1 time in 2^32, and the public-key checks
		// below are the backstop.
		if f.encrypted() {
			return nil, ErrWrongPassphrase
		}
		return nil, fmt.Errorf("%w: check values differ", errMalformed)
	}
	kt, ok := r.str()
	if !ok {
		return nil, errMalformed
	}
	if string(kt) != keyTypeEd {
		return nil, fmt.Errorf("%s is not read; kton signs with Ed25519 only", named("key type", kt))
	}
	pub, ok1 := r.str()
	priv, ok2 := r.str()
	_, ok3 := r.str() // comment
	if !ok1 || !ok2 || !ok3 || len(pub) != ed25519.PublicKeySize || len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: private key", errMalformed)
	}
	if len(r.b) >= f.blockSize() {
		return nil, fmt.Errorf("%w: padding", errMalformed)
	}
	for i, p := range r.b {
		if p != byte(i+1) {
			return nil, fmt.Errorf("%w: padding", errMalformed)
		}
	}
	// K5: the key is rebuilt from the seed; every stored public half must equal the derived one.
	k := ed25519.NewKeyFromSeed(priv[:ed25519.SeedSize])
	derived := k.Public().(ed25519.PublicKey)
	if subtle.ConstantTimeCompare(derived, f.pub) != 1 || subtle.ConstantTimeCompare(derived, pub) != 1 ||
		subtle.ConstantTimeCompare(derived, priv[ed25519.SeedSize:]) != 1 {
		clear(k)
		return nil, fmt.Errorf("%w: the stored public key does not match the private key", errMalformed)
	}
	return k, nil
}

// marshalOpenSSH writes priv in the OpenSSH form, encrypted with pass (aes256-ctr, bcrypt with a
// fresh random salt and the given rounds).
func marshalOpenSSH(priv ed25519.PrivateKey, pass []byte, rounds int) ([]byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, errors.New("not an Ed25519 private key")
	}
	if len(pass) == 0 {
		return nil, errors.New("an empty passphrase encrypts nothing")
	}
	priv = ed25519.NewKeyFromSeed(priv.Seed()) // K5: never write a stale public half
	defer clear(priv)
	pub := priv.Public().(ed25519.PublicKey)

	salt := make([]byte, saltLen)
	var check [4]byte
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	if _, err := rand.Read(check[:]); err != nil {
		return nil, err
	}

	var pubBlob []byte
	pubBlob = putStr(pubBlob, []byte(keyTypeEd))
	pubBlob = putStr(pubBlob, pub)

	var sec []byte
	sec = append(sec, check[:]...)
	sec = append(sec, check[:]...)
	sec = putStr(sec, []byte(keyTypeEd))
	sec = putStr(sec, pub)
	sec = putStr(sec, priv)
	sec = putStr(sec, nil) // comment
	for i := 1; len(sec)%aes.BlockSize != 0; i++ {
		sec = append(sec, byte(i))
	}
	defer clear(sec)

	k, err := bcrypt_pbkdf.Key(pass, salt, rounds, 32+aes.BlockSize)
	if err != nil {
		return nil, err
	}
	defer clear(k)
	blk, err := aes.NewCipher(k[:32])
	if err != nil {
		return nil, err
	}
	enc := make([]byte, len(sec))
	cipher.NewCTR(blk, k[32:]).XORKeyStream(enc, sec)

	var opts []byte
	opts = putStr(opts, salt)
	opts = binary.BigEndian.AppendUint32(opts, uint32(rounds))

	body := []byte(sshMagic)
	body = putStr(body, []byte(cipherCTR))
	body = putStr(body, []byte(kdfBcrypt))
	body = putStr(body, opts)
	body = binary.BigEndian.AppendUint32(body, 1)
	body = putStr(body, pubBlob)
	body = putStr(body, enc)
	return pem.EncodeToMemory(&pem.Block{Type: pemType, Bytes: body}), nil
}

func putStr(b, s []byte) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(s)))
	return append(b, s...)
}
