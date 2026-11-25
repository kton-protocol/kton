module kton.dev/nekton

go 1.22

// nekton reuses plankton's shared `core` (canonicalization, hashing, DSSE) and `keys` (a signer's key
// file, #277; it brings golang.org/x/crypto, x/term and x/sys, required indirectly below) - the
// allowed nekton -> plankton direction. Inside this repository ../../go.work resolves it to the
// sibling tree, so a change to plankton is visible here without a tag; the require below is what
// anyone OUTSIDE the workspace gets, and `go install` refuses a module carrying a replace - which
// is why this is a real version and not `v0.0.0` behind a replace directive.
require kton.dev/plankton v0.5.1

require (
	golang.org/x/crypto v0.33.0 // indirect
	golang.org/x/sys v0.30.0 // indirect
	golang.org/x/term v0.29.0 // indirect
)
