#!/usr/bin/env bash
set -Eueo pipefail
trap 'rc=$?; echo "error code $rc in $(caller) line $LINENO :: ${BASH_COMMAND}"; exit $rc' ERR
[ -n "${AWS_ACCESS_KEY_ID}" ]
[ -n "${AWS_SECRET_ACCESS_KEY}" ]
[ -n "${AWS_ENDPOINT}" ]

SCRIPTDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

source $SCRIPTDIR/require.sh

#setup tmpdir for testfiles and cleanup
TMPDIR=$(mktemp -d -t tmp.XXXXXXXXXX)
cleanup(){
	rm -rf "$TMPDIR"
}
trap cleanup EXIT

SRC_DIR=$TMPDIR/source
DST_DIR=$TMPDIR/dst
DST_DIR_MULTIPART=$TMPDIR/dst-multipart

# trim the protocol from the start of the endpoint (if present)
SERVER_NAME="${AWS_ENDPOINT#*//}"

mkdir -p "$SRC_DIR" "$DST_DIR" #"$DST_DIR_MULTIPART"

random_bytes_file () {
	size=$1
	output=$2
	dd if=/dev/urandom of="$output" count=1 bs="$size" >/dev/null 2>&1
}

random_bytes_file "1MiB"  "$SRC_DIR/backup-testfile-1MiB"  # create 1MiB file of random bytes (remote)
random_bytes_file "10MiB" "$SRC_DIR/backup-testfile-10MiB" # create 1-MiB file of random bytes (remote)

export PASSPHRASE="PASSPHRASE"

# duplicity 0.8.x w/ boto3 doesn't seem to create buckets anymore
aws s3 --endpoint "$AWS_ENDPOINT" mb s3://duplicity
aws s3 --endpoint "$AWS_ENDPOINT" mb s3://duplicity-multipart

duplicity -v9 --s3-endpoint-url=${AWS_ENDPOINT} "$SRC_DIR" "boto3+s3://duplicity/" --s3-unencrypted-connection

duplicity -v9 --s3-endpoint-url=${AWS_ENDPOINT} "boto3+s3://duplicity/" "$DST_DIR" --s3-unencrypted-connection

require_equal_files_content "$SRC_DIR/backup-testfile-1MiB"  "$DST_DIR/backup-testfile-1MiB"
require_equal_files_content "$SRC_DIR/backup-testfile-10MiB" "$DST_DIR/backup-testfile-10MiB"

# use multipart upload
duplicity -v9 --s3-endpoint-url=${AWS_ENDPOINT} "$SRC_DIR" "boto3+s3://duplicity-multipart/" --s3-unencrypted-connection --s3-use-multiprocessing --s3-multipart-max-procs 2 --s3-multipart-chunk-size 2097152

duplicity -v9 --s3-endpoint-url=${AWS_ENDPOINT} "boto3+s3://duplicity-multipart/" $DST_DIR_MULTIPART --s3-unencrypted-connection

require_equal_files_content "$SRC_DIR/backup-testfile-1MiB"  "$DST_DIR_MULTIPART/backup-testfile-1MiB"
require_equal_files_content "$SRC_DIR/backup-testfile-10MiB" "$DST_DIR_MULTIPART/backup-testfile-10MiB"