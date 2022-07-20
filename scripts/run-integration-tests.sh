#!/usr/bin/env bash
set -euo pipefail

SCRIPTDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

TEST=${1:-}
if [ -n "$TEST" ]; then
	"$SCRIPTDIR"/../gateway-st/testsuite/integration/"$TEST".sh
	exit $?
fi

"$SCRIPTDIR"/../gateway-st/testsuite/integration/awscli.sh
"$SCRIPTDIR"/../gateway-st/testsuite/integration/awscli_multipart.sh
"$SCRIPTDIR"/../gateway-st/testsuite/integration/duplicity.sh
"$SCRIPTDIR"/../gateway-st/testsuite/integration/duplicati.sh
"$SCRIPTDIR"/../gateway-st/testsuite/integration/https.sh
"$SCRIPTDIR"/../gateway-st/testsuite/integration/rclone.sh
"$SCRIPTDIR"/../gateway-st/testsuite/integration/s3fs.sh
