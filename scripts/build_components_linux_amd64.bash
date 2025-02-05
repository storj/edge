#!/usr/bin/env bash
set -euxo pipefail

git config --global --add safe.directory '*'

COMPONENTS=${1}
GO_VERSION=${2}

GOGO_VERSION=go${GO_VERSION}

COM=$(git rev-parse --short HEAD)
OUT="release/${COM}"
TAG=$(git describe --tags --exact-match --match v[0-9]*.[0-9]*.[0-9]*) && OUT="${OUT}-${TAG}" || TAG="v0.0.0"
OUT="${OUT}-${GOGO_VERSION}"
DIR=$(mktemp -d)

wget -P ${DIR} https://github.com/amwolff/go/archive/refs/tags/${GOGO_VERSION}.tar.gz
mkdir ${DIR}/${GOGO_VERSION}
tar -xzf ${DIR}/${GOGO_VERSION}.tar.gz --strip-components=1 -C ${DIR}/${GOGO_VERSION}
cd ${DIR}/${GOGO_VERSION}/src
./make.bash
cd -

for C in ${COMPONENTS//,/ }; do
    GOOS=linux GOARCH=amd64 ${DIR}/${GOGO_VERSION}/bin/go build \
        -o ${OUT}/${C}_linux_amd64 \
        -ldflags "-X storj.io/common/version.buildTimestamp=$(date +%s) -X storj.io/common/version.buildCommitHash=${COM} -X storj.io/common/version.buildVersion=${TAG} -X storj.io/common/version.buildRelease=true" \
        ./cmd/${C}
done
