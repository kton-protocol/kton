#!/usr/bin/env bash
# Shared store reader for the attack PoCs. Source it; do not run it.
#
# WHY THIS EXISTS: a PoC that globs the on-disk store hardcodes a layout, so it reports
# VULNERABLE the day the layout changes - a false alarm that costs exactly the attention a
# real regression needs. co-signer-drop did this: it read `objects/sha256/*.json`, and the
# #41 subnekton layout turned a still-holding property into a red gate. Read through this
# helper instead, and a PoC survives the next layout too.
#
# A nekton store is one JSONL file per subnekton since #41 (objects/**/*.nekton.jsonl, one
# record per line), plus one .json per claim for stores written before it. Both are read.

# nekton_records <nekton-dir> - print one compact JSON record per line.
nekton_records() {
  local d="${1:?nekton_records: need a nekton dir}"
  local f line
  find "$d/objects" -type f -name '*.nekton.jsonl' 2>/dev/null | sort | while IFS= read -r f; do
    while IFS= read -r line; do
      [ -n "$line" ] && printf '%s\n' "$line"
    done < "$f"
  done
  find "$d/objects" -type f -name '*.json' 2>/dev/null | sort | while IFS= read -r f; do
    jq -c . < "$f" 2>/dev/null || true
  done
}

# nekton_record_files <nekton-dir> <out-dir> - write each record to its own file (for the
# commands that take an envelope path, e.g. `nekton export`), and print the paths.
nekton_record_files() {
  local d="${1:?nekton_record_files: need a nekton dir}"
  local o="${2:?nekton_record_files: need an out dir}"
  mkdir -p "$o"
  nekton_records "$d" | {
    local i=0 rec p
    while IFS= read -r rec; do
      i=$((i + 1))
      p=$(printf '%s/%04d.json' "$o" "$i")
      printf '%s\n' "$rec" > "$p"
      printf '%s\n' "$p"
    done
  }
}
