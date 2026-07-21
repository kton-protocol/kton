package main

import _ "embed"

// manPage is the plankton(1) manual page, embedded so the binary is self-documenting offline.
// `plankton man` prints it (roff source; pipe to `man -l -` to render). The binary never shells
// out to man - it documents, it does not execute.
//
//go:embed plankton.1
var manPage string
