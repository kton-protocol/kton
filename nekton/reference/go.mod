module kton.dev/nekton

go 1.22

// Resolved locally via the workspace (../../go.work). nekton reuses plankton's shared `core`
// package only (canonicalization, hashing, DSSE) - the allowed nekton -> plankton direction.
require kton.dev/plankton v0.0.0

replace kton.dev/plankton => ../../reference
