Test keys made with `ssh-keygen` (OpenSSH 9.6), for `keys_test.go` only. They are public on purpose
and protect nothing. `encrypted.key` has the passphrase `correct horse`; `plain-openssh.key` has none;
`rsa.key` is there to be refused (kton signs with Ed25519 only).
