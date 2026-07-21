package main

import _ "embed"

// manPage is the kton(1) manual page, embedded so the binary is self-documenting offline.
//
//go:embed kton.1
var manPage string
