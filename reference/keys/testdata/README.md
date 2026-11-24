Test keys made with `ssh-keygen` (OpenSSH 9.6), for `keys_test.go` and the fuzz corpora only. They
are public on purpose and protect nothing.

- `encrypted.key`: passphrase `correct horse`, bcrypt rounds 24 (ssh-keygen's default);
- `encrypted-r1.key`, `encrypted-r16.key`, `encrypted-r64.key`: the same passphrase at rounds 1,
  16 and 64 (`ssh-keygen -t ed25519 -a <rounds>`), kton-review A2 on #277;
- `plain-openssh.key`: no passphrase;
- `rsa.key`: there to be refused (kton signs with Ed25519 only).

Each `.pub` is what ssh-keygen wrote beside its key.
