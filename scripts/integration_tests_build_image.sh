#!/usr/bin/env bash
set -euo pipefail

COMPONENT=${1:-}
BUILD_NUMBER=${2:-}
GO_VERSION=${3:-}
CGO_ENABLED=${CGO_ENABLED:-1}

if [ -z "$COMPONENT" ]; then
	echo "Missing first arg component, e.g. gateway-mt"
	exit 2
fi
if [ -z "$BUILD_NUMBER" ]; then
	echo "Missing second arg build number, e.g. 123"
	exit 2
fi
if [ -z "$GO_VERSION" ]; then
	echo "Missing third arg Go version, e.g. 1.17.5"
	exit 2
fi

if go env > /dev/null; then
	PKG_CACHE_PATH=$(go env GOPATH)
	BUILD_CACHE_PATH=$(go env GOCACHE)
	GOARCH=$(go env GOARCH)
else
	# go is not installed, make a few assumptions about environment
	mkdir -p /tmp/go-pkg
	PKG_CACHE_PATH=/tmp/go-pkg
	mkdir -p /tmp/go-cache
	BUILD_CACHE_PATH=/tmp/go-cache
	GOARCH=amd64
fi

case $GOARCH in
	arm)   DOCKER_ARCH=arm32v6 ;;
	arm64) DOCKER_ARCH=arm64v8 ;;
	*)     DOCKER_ARCH=amd64   ;;
esac

docker run \
	-u "$(id -u)":"$(id -g)" \
	-v "$PWD":/go/build \
	-v "$PKG_CACHE_PATH":/go/pkg \
	-v "$BUILD_CACHE_PATH":/tmp/.cache/go-build \
	-e GOARM=6 -e GOOS=linux -e GOARCH="$GOARCH" -e GOPROXY -e CGO_ENABLED \
	-w /go/build \
	--rm storjlabs/golang:"$GO_VERSION" \
	go build -o release/"$BUILD_NUMBER"/"$COMPONENT"_linux_"$GOARCH" \
		storj.io/edge/cmd/"$COMPONENT"

trap 'rm -r release/"$BUILD_NUMBER"' EXIT

docker build \
	--build-arg TAG="$BUILD_NUMBER" \
	--build-arg GOARCH="$GOARCH" \
	--build-arg DOCKER_ARCH="$DOCKER_ARCH" \
	--label build="$BUILD_NUMBER" \
	-t storjlabs/"$COMPONENT":"$BUILD_NUMBER" \
	-f cmd/"$COMPONENT"/Dockerfile .
