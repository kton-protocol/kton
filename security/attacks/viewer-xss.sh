#!/usr/bin/env bash
# viewer-xss: a claim by field carrying markup rendered as a live <img onerror> in a verified node. FIXED b8a642a.
echo "nekton claim by=<img src=x onerror=...> -> unescaped in the viewer panel; FIXED b8a642a (HTML-escape record-derived fields)."
