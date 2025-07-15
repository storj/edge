#!/usr/bin/env bash
set -euxo pipefail

COMPONENTS=${1}
OUT=${2}

REVISION=$(git rev-parse --short HEAD)
VERSION=$(git describe --tags --exact-match --match v[0-9]*.[0-9]*.[0-9]*) || VERSION="v0.0.0"

for C in ${COMPONENTS//,/ }; do
    for ARCH in arm arm64 amd64; do
        CGO_ENABLED=0 GOOS=linux GOARCH=${ARCH} go build \
            -o "${OUT}/${C}_linux_${ARCH}" \
            -ldflags "-X storj.io/common/version.buildTimestamp=$(date +%s) -X storj.io/common/version.buildCommitHash=${REVISION} -X storj.io/common/version.buildVersion=${VERSION} -X storj.io/common/version.buildRelease=true" \
            "./cmd/${C}"
    done
done
