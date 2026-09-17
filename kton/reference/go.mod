module kton.dev/kton

go 1.22

// kton is the cockpit that CONDUCTS both kernels - it imports plankton AND nekton and
// reimplements nothing. This is the ONLY module allowed to depend on both; the dependency
// direction is kton -> {plankton, nekton}, and nothing ever depends on kton. The kernels
// stay network-free (WASM-compilable); kton is where the port/HTTP/Rekor/blob surface lives.
// Inside this repository ../../go.work resolves both to the sibling trees, so a change to either
// kernel is visible here without a tag. The requires below are what anyone OUTSIDE the workspace
// gets, and `go install` refuses a module carrying a replace directive - which is why these are
// real versions. They are also why the three modules must be tagged in dependency order:
// plankton, then nekton, then kton.
require (
	kton.dev/nekton v0.2.1
	kton.dev/plankton v0.2.1
)
