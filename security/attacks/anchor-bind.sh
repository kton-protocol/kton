#!/usr/bin/env bash
# anchor-bind: a hostile Rekor endpoint replays a genuine, UNRELATED entry; kton reported it as an
# "independent witness" for a record not in the log. FIXED (b92c3b3): anchor binds the returned entry to
# the submitted record. NOTE: needs a LOCAL MOCK Rekor endpoint (never point at real Rekor). Documented repro.
echo "see b92c3b3: kton anchor now decodes entry.Body and requires it to embed the submitted envelope."
echo "repro (local mock only): PLANKTON_REKOR_URL=http://127.0.0.1:PORT (a mock returning a genuine unrelated"
echo "entry) + kton anchor <yourrecord> <pub>; pre-fix -> 'independent witness'; post-fix -> rejected."
