module kton.dev/kton

go 1.22

// kton is the cockpit that CONDUCTS both kernels - it imports plankton AND nekton and
// reimplements nothing. This is the ONLY module allowed to depend on both; the dependency
// direction is kton -> {plankton, nekton}, and nothing ever depends on kton. The kernels
// stay network-free (WASM-compilable); kton is where the port/HTTP/Rekor/blob surface lives.
// Resolved locally via the workspace (../../go.work).
require (
	kton.dev/nekton v0.0.0
	kton.dev/plankton v0.0.0
)

replace kton.dev/plankton => ../../reference

replace kton.dev/nekton => ../../nekton/reference
