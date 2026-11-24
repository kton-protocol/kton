// A test-only module (kton-review A4 on #277): golang.org/x/crypto/ssh as an oracle for the
// kernel's own OpenSSH key reader. It is its own module so that the kernel never depends on
// x/crypto/ssh; nothing imports it, and it is not in go.work. Run with GOWORK=off.
module kton.dev/plankton-keys-oracle

go 1.22

require (
	golang.org/x/crypto v0.33.0
	kton.dev/plankton v0.0.0
)

require (
	golang.org/x/sys v0.30.0 // indirect
	golang.org/x/term v0.29.0 // indirect
)

replace kton.dev/plankton => ../..
