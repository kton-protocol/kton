package registry

import "kton.dev/plankton/core"

// ReadPosition reads the store's position without opening it (#233): equal positions mean nothing
// changed; any difference means Open it and apply Records(since). See core.Position.
func ReadPosition(dir string) (core.Position, error) { return core.ReadPosition(dir) }
