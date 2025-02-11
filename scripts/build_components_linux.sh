#!/usr/bin/env bash
set -euxo pipefail

COMPONENTS=${1}
GO_VERSION=${2}
OUT=${3}

GOGO_VERSION=go${GO_VERSION}

REVISION=$(git rev-parse --short HEAD)
VERSION=$(git describe --tags --exact-match --match v[0-9]*.[0-9]*.[0-9]*) || VERSION="v0.0.0"
DIR=$(mktemp -d)

wget -P "${DIR}" "https://github.com/amwolff/go/archive/refs/tags/${GOGO_VERSION}.tar.gz"
mkdir "${DIR}/${GOGO_VERSION}"
tar -xzf "${DIR}/${GOGO_VERSION}.tar.gz" --strip-components=1 -C "${DIR}/${GOGO_VERSION}"
cd "${DIR}/${GOGO_VERSION}/src"
./make.bash
cd -

for C in ${COMPONENTS//,/ }; do
    for ARCH in arm arm64 amd64; do
        CGO_ENABLED=0 GOOS=linux GOARCH=${ARCH} "${DIR}/${GOGO_VERSION}/bin/go" build \
            -o "${OUT}/${C}_linux_${ARCH}" \
            -ldflags "-X storj.io/common/version.buildTimestamp=$(date +%s) -X storj.io/common/version.buildCommitHash=${REVISION} -X storj.io/common/version.buildVersion=${VERSION} -X storj.io/common/version.buildRelease=true" \
            "./cmd/${C}"
    done
done
