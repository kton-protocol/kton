#!/usr/bin/env bash
# concurrency-races: concurrent same-file writers corrupted objects and dropped a co-signature (non-atomic os.WriteFile). FIXED af3cefa.
echo "parallel add/union into one registry -> torn object / dropped co-signature; FIXED af3cefa (atomic temp+rename + locked union)."
