#!/usr/bin/env bash
set -euo pipefail

if ! uplink &> /dev/null; then
    echo "uplink command not found"
    exit 1
fi
if ! curl --version &> /dev/null; then
    echo "curl command not found"
    exit 1
fi
if [ $# -eq 0 ]; then
    echo "usage: $0 <BUCKET> <CONCURRENCY_LIMIT> <LINKSHARING_URL>"
    echo "example: $0 mybucket 100 https://link.storjshare.io"
    exit 1
fi
if [ -z "$ACCESS_GRANT" ]; then
    echo "ACCESS_GRANT env var not defined"
    exit 1
fi
if [ -z "$1" ]; then
    echo "Bucket name not provided"
    exit 1
fi

BUCKET=$1
CONCURRENCY_LIMIT=${2:-100} # second argument, default to 100
LINKSHARING_URL=${3:-"https://link.storjshare.io"} # third argument
AUTH_URL="https://auth.storjshare.io"
EXPIRE_AFTER="+2h"

echo "Testing using files in sj://$BUCKET"
echo "Concurrency limit set to $CONCURRENCY_LIMIT"
echo "Using linksharing: $LINKSHARING_URL"

FILES=$(uplink --access "$ACCESS_GRANT" ls "sj://$BUCKET" | awk '{print $5}')
if [ -z "$FILES" ]; then
    echo "No files found"
    exit 1
fi

SHARE_URL=$(uplink share --access "$ACCESS_GRANT" \
    --auth-service "$AUTH_URL" \
    --base-url "$LINKSHARING_URL" \
    --not-after "$EXPIRE_AFTER" \
    --readonly \
    --url \
    "sj://$BUCKET" | grep -e "^URL\\s*:" | awk '{print $3}')


# fallback for older curl versions that don't have the parallel downloads feature.
CURL_VERSION=$(curl --version | head -n1 | awk '{print $2}')
CURL_VERSION=${CURL_VERSION%.*} # strip the last bit of the version so we can compare, e.g. 7.68.0 -> 7.68
if [ "$(bc -l <<< "$CURL_VERSION < 7.68")" -eq 1 ]; then
    CURL_PIDS=()
    cleanup_curl_pids() {
        for PID in "${CURL_PIDS[@]}"; do
            kill "$PID" || true
        done
    }
    trap cleanup_curl_pids SIGINT SIGTERM
    i=0
    for FILE in $FILES; do
        if [ "$i" -ge "$CONCURRENCY_LIMIT" ]; then
            break
        fi
        curl "${SHARE_URL}${FILE}?download=1" -s -o /dev/null &
        CURL_PIDS+=($!)
        ((i=i+1))
    done
    wait
    echo "Done"
    exit
fi

URLS_FILE=$(mktemp /tmp/testXXXXXXX)
trap 'rm "$URLS_FILE"' EXIT

IFS=$'\n'
for FILE in $FILES; do
    URL="${SHARE_URL}${FILE}?download=1"
    printf "url=%s\\noutput=/dev/null\\n" "$URL" >> "$URLS_FILE"
done

curl --parallel \
    --parallel-immediate \
    --parallel-max "$CONCURRENCY_LIMIT" \
    --config "$URLS_FILE"

echo "Done"
