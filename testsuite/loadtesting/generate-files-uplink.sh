#!/usr/bin/env bash
set -euo pipefail

if ! uplink &> /dev/null; then
    echo "uplink command not found"
    exit 1
fi
if [ -z "$ACCESS_GRANT" ]; then
    echo "ACCESS_GRANT env var not defined"
    exit 1
fi

BUCKET=${1:-}
if [ -z "$BUCKET" ]; then
    BUCKET="test-files-$RANDOM"
    echo "No bucket name provided. Generating bucket name $BUCKET and creating"
    uplink --access "$ACCESS_GRANT" mb "sj://$BUCKET"
fi

FILE_SIZE_MB=128
NUM_FILES=100
TMPFILES=()
cleanup() {
    for TMPFILE in "${TMPFILES[@]}"; do
        test -f "$TMPFILE" && rm "$TMPFILE"
    done
}
trap cleanup EXIT

for ((i=0;i<NUM_FILES;i++)); do
    TMPFILE="$(mktemp /tmp/testXXXXXXX).dat"
    TMPNAME="$(basename "$TMPFILE")"
    dd if=/dev/random of="$TMPFILE" bs=1048576 count="$FILE_SIZE_MB" &> /dev/null
    TMPFILES+=("$TMPFILE")
    uplink --access "$ACCESS_GRANT" cp "$TMPFILE" "sj://$BUCKET/$TMPNAME"
done

echo "Test files created in sj://$BUCKET"