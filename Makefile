GO_VERSION ?= 1.15.5
GOOS ?= linux
GOARCH ?= amd64
GOPATH ?= $(shell go env GOPATH)
COMPONENTLIST := stargate authservice
COMPOSE_PROJECT_NAME := ${TAG}-$(shell git rev-parse --abbrev-ref HEAD)
BRANCH_NAME ?= $(shell git rev-parse --abbrev-ref HEAD | sed "s!/!-!g")
ifeq (${BRANCH_NAME},main)
TAG    := $(shell git rev-parse --short HEAD)-go${GO_VERSION}
BRANCH_NAME :=
else
TAG    := $(shell git rev-parse --short HEAD)-${BRANCH_NAME}-go${GO_VERSION}
ifneq (,$(shell git describe --tags --exact-match --match "v[0-9]*\.[0-9]*\.[0-9]*"))
LATEST_TAG := latest
endif
endif
RELEASE_BUILD_REQUIRED ?= false

FILEEXT :=
ifeq (${GOOS},windows)
FILEEXT := .exe
endif

DOCKER_BUILD := docker build \
	--build-arg TAG=${TAG}

.DEFAULT_GOAL := help
.PHONY: help
help:
	@awk 'BEGIN { \
		FS = ":.*##"; \
		printf "\nUsage:\n  make \033[36m<target>\033[0m\n"\
	} \
	/^[a-zA-Z_-]+:.*?##/ { \
		printf "  \033[36m%-17s\033[0m %s\n", $$1, $$2 \
	} \
	/^##@/ { \
		printf "\n\033[1m%s\033[0m\n", substr($$0, 5) \
	} ' $(MAKEFILE_LIST)

##@ Dependencies

.PHONY: build-dev-deps
build-dev-deps: ## Install dependencies for builds
	go get golang.org/x/tools/cover
	go get github.com/josephspurrier/goversioninfo/cmd/goversioninfo

.PHONY: lint
lint: ## Analyze and find programs in source code
	@echo "Running ${@}"
	@golangci-lint run

.PHONY: goimports-fix
goimports-fix: ## Applies goimports to every go file (excluding vendored files)
	goimports -w -local storj.io $$(find . -type f -name '*.go' -not -path "*/vendor/*")

.PHONY: goimports-st
goimports-st: ## Applies goimports to every go file in `git status` (ignores untracked files)
	@git status --porcelain -uno|grep .go|grep -v "^D"|sed -E 's,\w+\s+(.+->\s+)?,,g'|xargs -I {} goimports -w -local storj.io {}

.PHONY: build-packages
build-packages: build-packages-normal build-packages-race ## Test docker images locally
build-packages-normal:
	go build -v ./...
build-packages-race:
	go build -v -race ./...

##@ Test

.PHONY: test
test: ## Run tests on source code (jenkins)
	go test -race -v -cover -coverprofile=.coverprofile ./...
	@echo done

##@ Build

.PHONY: images
images: stargate-image authservice-image ## Build stargate and authservice Docker images
	echo Built version: ${TAG}

.PHONY: stargate-image
stargate-image: stargate_linux_arm64 stargate_linux_amd64 ## Build stargate Docker image
	${DOCKER_BUILD} --pull=true -t storjlabs/stargate:${TAG}-amd64 \
		-f cmd/stargate/Dockerfile .
	${DOCKER_BUILD} --pull=true -t storjlabs/stargate:${TAG}-arm32v6 \
		--build-arg=GOARCH=arm --build-arg=DOCKER_ARCH=arm32v6 \
		-f cmd/stargate/Dockerfile .
	${DOCKER_BUILD} --pull=true -t storjlabs/stargate:${TAG}-aarch64 \
		--build-arg=GOARCH=arm64 --build-arg=DOCKER_ARCH=aarch64 \
		-f cmd/stargate/Dockerfile .

.PHONY: authservice-image
authservice-image: authservice_linux_arm64 authservice_linux_amd64 ## Build authservice Docker image
	${DOCKER_BUILD} --pull=true -t storjlabs/authservice:${TAG}-amd64 \
		-f cmd/authservice/Dockerfile .
	${DOCKER_BUILD} --pull=true -t storjlabs/authservice:${TAG}-arm32v6 \
		--build-arg=GOARCH=arm --build-arg=DOCKER_ARCH=arm32v6 \
		-f cmd/authservice/Dockerfile .
	${DOCKER_BUILD} --pull=true -t storjlabs/authservice:${TAG}-aarch64 \
		--build-arg=GOARCH=arm64 --build-arg=DOCKER_ARCH=aarch64 \
		-f cmd/authservice/Dockerfile .

.PHONY: binary
binary:
	@if [ -z "${COMPONENT}" ]; then echo "Try one of the following targets instead:" \
		&& for b in binaries ${BINARIES}; do echo "- $$b"; done && exit 1; fi
	storj-release --components="cmd/${COMPONENT}" --go-version="${GO_VERSION}" --branch="${BRANCH_NAME}"

.PHONY: binaries
binaries: ${BINARIES} ## Build stargate and authservice binaries (jenkins)
	for C in ${COMPONENTLIST}; do\
		$(MAKE) binary COMPONENT=$$C \
	; done

##@ Deploy

.PHONY: push-images
push-images: ## Push Docker images to Docker Hub (jenkins)
	# images have to be pushed before a manifest can be created
	for c in ${COMPONENTLIST}; do \
		docker push storjlabs/$$c:${TAG}-amd64 \
		&& docker push storjlabs/$$c:${TAG}-arm32v6 \
		&& docker push storjlabs/$$c:${TAG}-aarch64 \
		&& for t in ${TAG} ${LATEST_TAG}; do \
			docker manifest create storjlabs/$$c:$$t \
			storjlabs/$$c:${TAG}-amd64 \
			storjlabs/$$c:${TAG}-arm32v6 \
			storjlabs/$$c:${TAG}-aarch64 \
			&& docker manifest annotate storjlabs/$$c:$$t storjlabs/$$c:${TAG}-amd64 --os linux --arch amd64 \
			&& docker manifest annotate storjlabs/$$c:$$t storjlabs/$$c:${TAG}-arm32v6 --os linux --arch arm --variant v6 \
			&& docker manifest annotate storjlabs/$$c:$$t storjlabs/$$c:${TAG}-aarch64 --os linux --arch arm64 \
			&& docker manifest push --purge storjlabs/$$c:$$t \
		; done \
	; done

.PHONY: binaries-upload
binaries-upload: ## Upload binaries to Google Storage (jenkins)
	cd "release/${TAG}"; for f in *; do \
		c="$${f%%_*}" \
		&& if [ "$${f##*.}" != "$${f}" ]; then \
			ln -s "$${f}" "$${f%%_*}.$${f##*.}" \
			&& zip "$${f}.zip" "$${f%%_*}.$${f##*.}" \
			&& rm "$${f%%_*}.$${f##*.}" \
		; else \
			ln -sf "$${f}" "$${f%%_*}" \
			&& zip "$${f}.zip" "$${f%%_*}" \
			&& rm "$${f%%_*}" \
		; fi \
	; done
	cd "release/${TAG}"; gsutil -m cp -r *.zip "gs://storj-v3-alpha-builds/${TAG}/"

##@ Clean

.PHONY: clean
clean: test-docker-clean binaries-clean clean-images ## Clean docker test environment, local release binaries, and local Docker images

.PHONY: binaries-clean
binaries-clean: ## Remove all local release binaries (jenkins)
	rm -rf release

.PHONY: clean-images
clean-images:
	-docker rmi storjlabs/stargate:${TAG}
	-docker rmi storjlabs/authservice:${TAG}

.PHONY: test-docker-clean
test-docker-clean: ## Clean up Docker environment used in test-docker target
	-docker-compose down --rmi all

.PHONY: bump-dependencies
bump-dependencies:
	go get storj.io/common@master storj.io/private@master storj.io/uplink@master
	go mod tidy
	cd testsuite;\
		go get storj.io/common@master storj.io/storj@master storj.io/uplink@master;\
		go mod tidy
