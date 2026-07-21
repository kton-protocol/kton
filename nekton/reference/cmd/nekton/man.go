package main

import _ "embed"

// manPage is the nekton(1) manual page, embedded so the binary is self-documenting offline.
//
//go:embed nekton.1
var manPage string
