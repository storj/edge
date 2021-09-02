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
SYNC_DST_DIR=$TMPDIR/sync-dst
mkdir -p "$SRC_DIR" "$DST_DIR" "$SYNC_DST_DIR"

export AWS_CONFIG_FILE=$TMPDIR/.aws/config

random_bytes_file () {
	count=$1
    size=$2
	output=$3
	dd if=/dev/urandom of="$output" count=$count bs="$size" >/dev/null 2>&1
}

random_bytes_file 1  1024      "$SRC_DIR/small-upload-testfile"     # create 1kb file of random bytes (inline)
random_bytes_file 9  1024x1024 "$SRC_DIR/big-upload-testfile"       # create 9mb file of random bytes (remote)
# this is special case where we need to test at least one remote segment and inline segment of exact size 0
# value is invalid until we will be able to configure segment size once again
random_bytes_file 64 1024x1024 "$SRC_DIR/multipart-upload-testfile"

BUCKET="bucket"
BUCKET_SYNC="bucket-sync"

echo "Creating Bucket"
aws s3 --endpoint "$AWS_ENDPOINT" mb "s3://$BUCKET"

echo "Uploading Files"
aws configure set default.s3.multipart_threshold 1TB
aws s3 --endpoint "$AWS_ENDPOINT" --no-progress cp "$SRC_DIR/small-upload-testfile" "s3://$BUCKET/small-testfile"
aws s3 --endpoint "$AWS_ENDPOINT" --no-progress cp "$SRC_DIR/big-upload-testfile"   "s3://$BUCKET/big-testfile"

echo "Testing presign"
URL=$(aws s3 --endpoint "$AWS_ENDPOINT" presign "s3://$BUCKET/big-testfile")
STATUS=$(curl -s -o "$TMPDIR/big-upload-testfile" -w "%{http_code}" "$URL")
require_equal_strings "$STATUS" "200"
require_equal_files_content "$SRC_DIR/big-upload-testfile" "$TMPDIR/big-upload-testfile"

echo "Testing presign expires"
URL=$(aws s3 --endpoint "$AWS_ENDPOINT" presign "s3://$BUCKET/big-testfile" --expires-in 1)
sleep 2
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$URL")
require_equal_strings "$STATUS" "403"

echo "Testing tagging"
touch "$TMPDIR/no-tags.json"
cat > "$TMPDIR/has-tags.json" << EOF
TAGSET	designation	confidential
EOF
aws --endpoint="$AWS_ENDPOINT" s3api get-object-tagging --bucket "$BUCKET" --key big-testfile --output text > "$TMPDIR/tags.json"
require_equal_files_content "$TMPDIR/tags.json" "$TMPDIR/no-tags.json"
aws --endpoint="$AWS_ENDPOINT" s3api put-object-tagging --bucket "$BUCKET" --key big-testfile --tagging '{"TagSet": [{ "Key": "designation", "Value": "confidential" }]}'
aws --endpoint="$AWS_ENDPOINT" s3api get-object-tagging --bucket "$BUCKET" --key big-testfile --output text > "$TMPDIR/tags.json"
require_equal_files_content "$TMPDIR/tags.json" "$TMPDIR/has-tags.json"
aws --endpoint="$AWS_ENDPOINT" s3api delete-object-tagging --bucket "$BUCKET" --key big-testfile
aws --endpoint="$AWS_ENDPOINT" s3api get-object-tagging --bucket "$BUCKET" --key big-testfile --output text > "$TMPDIR/tags.json"
require_equal_files_content "$TMPDIR/tags.json" "$TMPDIR/no-tags.json"

# Wait 5 seconds to trigger any error related to one of the different intervals
sleep 5

echo "Uploading Multipart File"
aws configure set default.s3.multipart_threshold 4KB
aws s3 --endpoint "$AWS_ENDPOINT" --no-progress cp "$SRC_DIR/multipart-upload-testfile" "s3://$BUCKET/multipart-testfile"

echo "Downloading Files"
aws s3 --endpoint "$AWS_ENDPOINT" ls "s3://$BUCKET"
aws s3 --endpoint "$AWS_ENDPOINT" --no-progress cp "s3://$BUCKET/small-testfile"     "$DST_DIR/small-download-testfile"
aws s3 --endpoint "$AWS_ENDPOINT" --no-progress cp "s3://$BUCKET/big-testfile"       "$DST_DIR/big-download-testfile"
aws s3 --endpoint "$AWS_ENDPOINT" --no-progress cp "s3://$BUCKET/multipart-testfile" "$DST_DIR/multipart-download-testfile"
aws s3 --endpoint "$AWS_ENDPOINT" rb "s3://$BUCKET" --force

require_equal_files_content "$SRC_DIR/small-upload-testfile"     "$DST_DIR/small-download-testfile"
require_equal_files_content "$SRC_DIR/big-upload-testfile"       "$DST_DIR/big-download-testfile"
require_equal_files_content "$SRC_DIR/multipart-upload-testfile" "$DST_DIR/multipart-download-testfile"

echo "Creating Bucket for sync test"
aws s3 --endpoint "$AWS_ENDPOINT" mb "s3://$BUCKET_SYNC"

echo "Sync Files"
aws s3 --endpoint "$AWS_ENDPOINT" --no-progress sync "$SRC_DIR" "s3://$BUCKET_SYNC"
aws s3 --endpoint "$AWS_ENDPOINT" --no-progress sync "s3://$BUCKET_SYNC" "$SYNC_DST_DIR"

aws s3 --endpoint "$AWS_ENDPOINT" rb "s3://$BUCKET_SYNC" --force

echo "Compare sync directories"
diff "$SRC_DIR" "$SYNC_DST_DIR"

echo "Deleting Files"

aws s3 --endpoint "$AWS_ENDPOINT" mb "s3://$BUCKET"

cat > "$TMPDIR/all-exist.json" << EOF
{
    "Objects": [
        {
            "Key": "data/small-download-testfile"
        },
        {
            "Key": "data/big-download-testfile"
        },
        {
            "Key": "data/multipart-download-testfile"
        }
    ]
}
EOF

cat > "$TMPDIR/some-exist.json" << EOF
{
    "Objects": [
        {
            "Key": "data/does-not-exist"
        },
        {
            "Key": "data/big-download-testfile"
        },
        {
            "Key": "data/multipart-download-testfile"
        }
    ]
}
EOF

cat > "$TMPDIR/none-exist.json" << EOF
{
    "Objects": [
        {
            "Key": "data/does-not-exist-1"
        },
        {
            "Key": "data/does-not-exist-2"
        },
        {
            "Key": "data/does-not-exist-3"
        }
    ]
}
EOF

for delete_set in all-exist.json some-exist.json none-exist.json; do
  aws s3 --endpoint "$AWS_ENDPOINT" --no-progress cp --recursive "$SRC_DIR" "s3://$BUCKET/data"
  aws s3api --endpoint "$AWS_ENDPOINT" \
    delete-objects --bucket "$BUCKET" --delete "file://$TMPDIR/$delete_set" > "$TMPDIR/$delete_set.result"

  grep 'Key' "$TMPDIR/$delete_set" | sort > "$TMPDIR/$delete_set.sorted"
  grep 'Key' "$TMPDIR/$delete_set.result" | sort > "$TMPDIR/$delete_set.result.sorted"

  cat "$TMPDIR/$delete_set.sorted"
  cat "$TMPDIR/$delete_set.result.sorted"

  require_equal_files_content "$TMPDIR/$delete_set.sorted" "$TMPDIR/$delete_set.result.sorted"
done

aws s3 --endpoint "$AWS_ENDPOINT" rb "s3://$BUCKET" --force
