COMPONENTLIST := gateway-mt authservice linksharing simplegateway mcp-server

#
# Common
#

.PHONY: help
help:
	@awk 'BEGIN { \
		FS = ":.*##"; \
		printf "\nUsage:\n  make \033[36m<target>\033[0m\n" \
	} \
	/^[a-zA-Z0-9_-]+:.*?##/ { \
		printf "  \033[36m%-32s\033[0m %s\n", $$1, $$2 \
	} \
	/^##@/ { \
		printf "\n\033[1m%s\033[0m\n", substr($$0, 5) \
	}' $(MAKEFILE_LIST)

.DEFAULT_GOAL := help

#
# Public Jenkins (commands below are used for local development and/or public Jenkins)
#

#@ Local development/Public Jenkins/Helpers

.PHONY: install-dev-dependencies
install-dev-dependencies: badgerauth-install-dependencies ## install-dev-dependencies assumes Go and cURL are installed
	# Storj-specific:
	go install github.com/storj/ci/check-mod-tidy@latest
	go install github.com/storj/ci/check-copyright@latest
	go install github.com/storj/ci/check-large-files@latest
	go install github.com/storj/ci/check-imports@latest
	go install github.com/storj/ci/check-peer-constraints@latest
	go install github.com/storj/ci/check-atomic-align@latest
	go install github.com/storj/ci/check-monkit@latest
	go install github.com/storj/ci/check-errs@latest
	go install github.com/storj/ci/check-downgrades@latest
	go install github.com/storj/ci/storj-release@latest

	# staticcheck:
	go install honnef.co/go/tools/cmd/staticcheck@latest

	# golangci-lint:
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.12.2

	# shellcheck (TODO(artur,sean): Windows)
ifneq ($(shell which apt-get),)
	sudo apt-get install -y shellcheck
else ifneq ($(shell which brew),)
	brew install shellcheck
else
	$(error Can't install shellcheck without a supported package manager)
endif

	go install github.com/google/go-licenses@v1.6.0

.PHONY: badgerauth-install-dependencies
badgerauth-install-dependencies:
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install storj.io/drpc/cmd/protoc-gen-go-drpc@latest

ifneq ($(shell which apt-get),)
	sudo apt-get install -y protobuf-compiler
else ifneq ($(shell which brew),)
	brew install protobuf
else
	$(error Can't install protobuf without a supported package manager)
endif

.PHONY: badgerauth-format-protobufs
badgerauth-format-protobufs:
ifeq ($(shell which clang-format),)
# If clang-format isn't found, we want to install it first:
ifneq ($(shell which apt-get),)
	sudo apt-get install -y clang-format
else ifneq ($(shell which brew),)
	brew install clang-format
else
	$(error Can't install clang-format without a supported package manager)
endif
endif

	clang-format -i pkg/auth/badgerauth/pb/badgerauth.proto
	clang-format -i pkg/auth/badgerauth/pb/badgerauth_admin.proto

.PHONY: bump-code-dependencies
bump-code-dependencies:
	go get storj.io/gateway@main && go mod tidy && cd testsuite && go mod tidy && \
	go get storj.io/storj@latest && go mod tidy

.PHONY: install-hooks
install-hooks: ## Install helpful Git hooks
	ln -s ../../githooks/pre-commit .git/hooks/pre-commit

##@ Local development/Public Jenkins/Lint

GOLANGCI_LINT_CONFIG ?= ../ci/.golangci.yml
GOLANGCI_LINT_CONFIG_TESTSUITE ?= ../../ci/.golangci.yml

.PHONY: lint
lint: ## Lint
	check-mod-tidy
	check-copyright
	check-large-files
	check-imports -race ./...
	check-peer-constraints -race
	check-atomic-align ./...
	check-monkit ./...
	check-errs ./...
	staticcheck ./...
	golangci-lint run --config ${GOLANGCI_LINT_CONFIG}
	check-downgrades

	go-licenses check --ignore "storj.io/dotworld,storj.io/edge" ./...

	# Prune .build (Python virtualenvs etc.) and testsuite@tmp (Jenkins). Use + so
	# any failed shellcheck invocation propagates a non-zero exit.
	find . \( -path ./.build -o -path ./testsuite@tmp \) -prune -o -name "*.sh" -type f -exec "shellcheck" "-x" "--format=gcc" {} +;

	# Execute lint-testsuite in testsuite directory:
	$(MAKE) -C testsuite -f ../Makefile lint-testsuite

.PHONY: lint-testsuite
lint-testsuite: ## Lint testsuite
	check-imports -race ./...
	check-atomic-align ./...
	check-monkit ./...
	check-errs ./...
	staticcheck ./...
	golangci-lint run --config ${GOLANGCI_LINT_CONFIG_TESTSUITE}

	go-licenses check --ignore "storj.io/dotworld,storj.io/edge" ./...

##@ Local development/Public Jenkins/Vet

.PHONY: vet
vet: ## Vet
	GOOS=linux   GOARCH=amd64 go vet ./...
	GOOS=linux   GOARCH=386   go vet ./...
	GOOS=linux   GOARCH=arm64 go vet ./...
	GOOS=linux   GOARCH=arm   go vet ./...
	GOOS=darwin  GOARCH=arm64 go vet -tags kqueue ./...
	GOOS=windows GOARCH=amd64 go vet ./...

##@ Local development/Public Jenkins/Test

JSON ?= false
SHORT ?= true
SKIP_TESTSUITE ?= false

.PHONY: test
test: test-testsuite ## Test
	go test -json=${JSON} -p 16 -parallel 4 -race -short=${SHORT} -timeout 10m -vet=off ./...

.PHONY: test-testsuite
test-testsuite: ## Test testsuite
ifeq (${SKIP_TESTSUITE},false)
	# Execute test-testsuite-do in testsuite directory:
	$(MAKE) -C testsuite -f ../Makefile test-testsuite-do
endif

.PHONY: test-testsuite-do
test-testsuite-do:
	go vet ./...
	go test -json=${JSON} -p 16 -parallel 4 -race -short=${SHORT} -timeout 10m -vet=off ./...

##@ Local development/Public Jenkins/Verification

.PHONY: verify
verify: lint cross-vet test ## Execute pre-commit verification

#
# Private Jenkins (commands below are used for releases/private Jenkins)
#

##@ Release/Private Jenkins/Build

GO_VERSION ?= 1.26.5
BRANCH_NAME ?= $(shell git rev-parse --abbrev-ref HEAD | sed "s!/!-!g")

ifeq (${BRANCH_NAME},main)
	TAG := $(shell git rev-parse --short HEAD)-go${GO_VERSION}
	BRANCH_NAME :=
else
	TAG := $(shell git rev-parse --short HEAD)-${BRANCH_NAME}-go${GO_VERSION}
	ifneq ($(shell git describe --tags --exact-match --match "v[0-9]*\.[0-9]*\.[0-9]*"),)
		LATEST_STABLE_TAG := latest
	endif
endif

DOCKER_BUILD := docker build --build-arg TAG=${TAG}

LATEST_DEV_TAG := dev

.PHONY: images
images: ## Build Docker images
	for c in ${COMPONENTLIST}; do \
		${DOCKER_BUILD} --platform linux/amd64 --pull=true -t storjlabs/$$c:${TAG}-amd64 \
			-f cmd/$$c/Dockerfile . \
		&& ${DOCKER_BUILD} --platform linux/arm/v6 --pull=true -t storjlabs/$$c:${TAG}-arm32v6 \
			--build-arg=GOARCH=arm \
			--build-arg=DOCKER_ARCH=arm32v6 \
			-f cmd/$$c/Dockerfile . \
		&& ${DOCKER_BUILD} --platform linux/arm64 --pull=true -t storjlabs/$$c:${TAG}-arm64v8 \
			--build-arg=GOARCH=arm64 \
			--build-arg=DOCKER_ARCH=arm64v8 \
			-f cmd/$$c/Dockerfile . \
		&& docker tag storjlabs/$$c:${TAG}-amd64 storjlabs/$$c:${LATEST_DEV_TAG} \
		&& echo Built $$c version: ${TAG} \
	; done

.PHONY: binaries
binaries: ${BINARIES} ## Build binaries
	# TODO(artur): we could use a bit of caching here, but that's not strictly necessary for now
	docker run --rm \
		-v $$PWD:/usr/src/edge \
		-w /usr/src/edge \
		-e GOCACHE=/tmp/go-pkg \
		-u $$(id -u):$$(id -g) \
		golang:"${GO_VERSION}" scripts/build_components_linux.sh "${COMPONENTLIST}" "release/${TAG}"

.PHONY: push-images
push-images: ## Push Docker images to Docker Hub
	# images have to be pushed before a manifest can be created
	for c in ${COMPONENTLIST}; do \
		docker push storjlabs/$$c:${TAG}-amd64 \
		&& docker push storjlabs/$$c:${TAG}-arm32v6 \
		&& docker push storjlabs/$$c:${TAG}-arm64v8 \
		&& for t in ${TAG} ${LATEST_DEV_TAG} ${LATEST_STABLE_TAG}; do \
			docker manifest create storjlabs/$$c:$$t \
			storjlabs/$$c:${TAG}-amd64 \
			storjlabs/$$c:${TAG}-arm32v6 \
			storjlabs/$$c:${TAG}-arm64v8 \
			&& docker manifest annotate storjlabs/$$c:$$t storjlabs/$$c:${TAG}-amd64 --os linux --arch amd64 \
			&& docker manifest annotate storjlabs/$$c:$$t storjlabs/$$c:${TAG}-arm32v6 --os linux --arch arm --variant v6 \
			&& docker manifest annotate storjlabs/$$c:$$t storjlabs/$$c:${TAG}-arm64v8 --os linux --arch arm64 --variant v8 \
			&& docker manifest push --purge storjlabs/$$c:$$t \
		; done \
	; done

.PHONY: binaries-upload
binaries-upload: ## Upload release binaries to GCS
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
	cd "release/${TAG}" \
		&& sha256sum *.zip > sha256sums \
		&& gsutil -m cp -r *.zip sha256sums "gs://storj-v3-alpha-builds/${TAG}/"

##@ Release/Private Jenkins/Clean

.PHONY: clean
clean: clean-binaries clean-images ## Remove local release binaries and local Docker images

.PHONY: clean-binaries
clean-binaries: ## Remove local release binaries
	rm -rf release

.PHONY: clean-images
clean-images:
	for c in ${COMPONENTLIST}; do \
		docker rmi -f $$(docker images -q "storjlabs/$$c:${TAG}-*") \
	; done

##@ Local development/Public Jenkins/Integration Test

BUILD_NUMBER ?= ${TAG}

# docker-compose project names disallow dots.
INTEGRATION_PROJECT     ?= integration-$(subst .,-,$(BUILD_NUMBER))
INTEGRATION_NETWORK     ?= integration-network-$(BUILD_NUMBER)
INTEGRATION_AUTHSERVICE ?= integration-authservice-$(BUILD_NUMBER)
INTEGRATION_GATEWAY     ?= integration-gateway-$(BUILD_NUMBER)
INTEGRATION_SATELLITE   ?= satellite-api:7777
INTEGRATION_COMPOSE     := docker compose -p $(INTEGRATION_PROJECT)
INTEGRATION_CREDENTIALS := $(INTEGRATION_COMPOSE) exec -T satellite-api storj-up credentials --s3 -e -a http://authservice:20000 -s $(INTEGRATION_SATELLITE)

# Storj satellite revision storj-up builds. Defaults to testsuite/go.mod's pin.
STORJ_REF ?= $(shell awk '$$1 == "storj.io/storj" {print $$2}' testsuite/go.mod)

.PHONY: integration-run
integration-run: ## Bring up the env, run all integration tests, tear it down (purges even on failure)
	$(MAKE) integration-env-start
	$(MAKE) integration-tests; rc=$$?; $(MAKE) integration-env-purge; exit $$rc

.PHONY: integration-tests
integration-tests: integration-gateway-st-tests integration-gateway-st-tests-s3fs integration-mint-tests integration-ceph-tests ## Run all integration tests (environment needs to be started first)

.PHONY: integration-env-start
integration-env-start: integration-checkout integration-image-build integration-network-create integration-services-start ## Start the integration environment

.PHONY: integration-env-purge
integration-env-purge: ## Tear down everything created by integration-env-start (idempotent)
	-docker ps -qf network=$(INTEGRATION_NETWORK) | xargs -r docker stop --timeout=1
	-docker rm -f $(INTEGRATION_AUTHSERVICE) $(INTEGRATION_GATEWAY)
	# No --rmi: keep shared base images (redis, spanner-emulator, storjup/build).
	-$(INTEGRATION_COMPOSE) down --volumes --remove-orphans --timeout 1 2>/dev/null
	-docker image ls -qf label=build=$(BUILD_NUMBER) | xargs -r docker rmi -f
	-docker network remove $(INTEGRATION_NETWORK)
	-rm -rf volumes gateway-st storj edge.Dockerfile storj.Dockerfile docker-compose.yaml

.PHONY: integration-env-logs
integration-env-logs: ## Retrieve logs from integration services
	-$(INTEGRATION_COMPOSE) logs
	-docker logs $(INTEGRATION_AUTHSERVICE)
	-docker logs $(INTEGRATION_GATEWAY)

# umask 0000 is needed for rclone tests so files can be cleaned up.
.PHONY: integration-gateway-st-tests
integration-gateway-st-tests: ## Run a single gateway-st subtest as $$TEST (environment needs to be started first)
	$$($(INTEGRATION_CREDENTIALS)) && \
	docker run \
	--network $(INTEGRATION_NETWORK) \
	-e AWS_ENDPOINT=https://gateway:20011 \
	-e "AWS_ACCESS_KEY_ID=$$AWS_ACCESS_KEY_ID" \
	-e "AWS_SECRET_ACCESS_KEY=$$AWS_SECRET_ACCESS_KEY" \
	-v $$PWD:/build \
	-w /build \
	--name integration-gateway-st-tests-${BUILD_NUMBER}-$$TEST \
	--entrypoint /bin/bash \
	--rm storjlabs/ci:latest \
	-c "umask 0000; gateway-st/testsuite/integration/$$TEST.sh"

# s3fs needs FUSE so it can't run as the host user.
.PHONY: integration-gateway-st-tests-s3fs
integration-gateway-st-tests-s3fs: ## Run the gateway-st s3fs subtest (privileged; environment needs to be started first)
	$$($(INTEGRATION_CREDENTIALS)) && \
	docker run \
	--cap-add SYS_ADMIN --device /dev/fuse --security-opt apparmor:unconfined \
	--network $(INTEGRATION_NETWORK) \
	-e AWS_ENDPOINT=https://gateway:20011 \
	-e "AWS_ACCESS_KEY_ID=$$AWS_ACCESS_KEY_ID" \
	-e "AWS_SECRET_ACCESS_KEY=$$AWS_SECRET_ACCESS_KEY" \
	-v $$PWD:/build \
	-w /build \
	--name integration-gateway-st-tests-s3fs-${BUILD_NUMBER} \
	--entrypoint /bin/bash \
	--rm storjlabs/ci:latest \
	-c "umask 0000; gateway-st/testsuite/integration/s3fs.sh"

# umask 0000 because the container runs as root and writes to bind-mounted /build/.build/.
.PHONY: integration-ceph-tests
integration-ceph-tests: ## Run ceph s3-tests suite (environment needs to be started first)
	$$($(INTEGRATION_CREDENTIALS)) && \
	docker run \
	--network $(INTEGRATION_NETWORK) \
	-e GATEWAY_0_ADDR=gateway:20010 \
	-e "GATEWAY_0_ACCESS_KEY=$$AWS_ACCESS_KEY_ID" \
	-e "GATEWAY_0_SECRET_KEY=$$AWS_SECRET_ACCESS_KEY" \
	-v $$PWD:/build \
	-w /build \
	--name integration-ceph-tests-${BUILD_NUMBER}-$$TEST \
	--entrypoint /bin/bash \
	--rm python:3.13-bookworm \
	-c "umask 0000; gateway-st/testsuite/ceph-s3-tests/run.sh"

.PHONY: integration-mint-tests
integration-mint-tests: ## Run mint test suite (environment needs to be started first)
	$$($(INTEGRATION_CREDENTIALS)) && \
	docker run \
	--network $(INTEGRATION_NETWORK) \
	-e SERVER_ENDPOINT=gateway:20010 \
	-e "ACCESS_KEY=$$AWS_ACCESS_KEY_ID" \
	-e "SECRET_KEY=$$AWS_SECRET_ACCESS_KEY" \
	-e ENABLE_HTTPS=0 \
	--name integration-mint-tests-${BUILD_NUMBER}-$$TEST \
	--rm storjlabs/gateway-mint:latest $$TEST

.PHONY: integration-checkout
integration-checkout:
	git clone --filter blob:none --depth 1 --no-tags --no-checkout https://github.com/storj/gateway-st gateway-st
	cd gateway-st && \
		git config core.sparsecheckout true && \
		echo "testsuite/integration" >> .git/info/sparse-checkout && \
		echo "testsuite/ceph-s3-tests" >> .git/info/sparse-checkout && \
		git checkout

.PHONY: integration-image-build
integration-image-build:
	for C in gateway-mt authservice; do \
		CGO_ENABLED=0 ./scripts/integration_tests_build_image.sh $$C ${BUILD_NUMBER} ${GO_VERSION} \
	; done

	storj-up init minimal,db && \
		storj-up build remote github minimal -b $(STORJ_REF) -c $(STORJ_REF) -s && \
		$(INTEGRATION_COMPOSE) build

.PHONY: integration-network-create
integration-network-create:
	docker network create $(INTEGRATION_NETWORK)

.PHONY: integration-services-start
integration-services-start:
	storj-up network set minimal,db $(INTEGRATION_NETWORK) && \
	storj-up network unset minimal,db default && \
	storj-up env setenv satellite-api STORJ_METAINFO_DELETE_OBJECTS_ENABLED=true && \
	storj-up env setenv satellite-api STORJ_METAINFO_BUCKET_TAGGING_ENABLED=true && \
	storj-up env set storagenode STORJUP_AUTHSERVICE=http://authservice:20000 && \
	storj-up port remove postgres 5432 && \
	storj-up port add postgres 5432 -e 5433 && \
	$(INTEGRATION_COMPOSE) up -d && \
	storj-up health -p 5433

	docker run \
	--network $(INTEGRATION_NETWORK) --network-alias authservice \
	--name $(INTEGRATION_AUTHSERVICE) \
	--rm -d storjlabs/authservice:${BUILD_NUMBER} run \
		--listen-addr 0.0.0.0:20000 \
		--drpc-listen-addr 0.0.0.0:20002 \
		--allowed-satellites $$($(INTEGRATION_COMPOSE) exec -T satellite-api storj-up util node-id /storj/.local/share/storj/identity/satellite-api/identity.cert)@$(INTEGRATION_SATELLITE) \
		--auth-token super-secret \
		--endpoint http://gateway:20010 \
		--kv-backend badger://

	mkdir -p volumes/gateway
	openssl req \
		-x509 \
		-newkey rsa:4096 \
		-keyout volumes/gateway/cert.key \
		-out volumes/gateway/cert.crt \
		-nodes \
		-subj '/CN=gateway' \
		-addext "subjectAltName = DNS:gateway"

	docker run \
	--network $(INTEGRATION_NETWORK) --network-alias gateway \
	--name $(INTEGRATION_GATEWAY) \
	--volume $$PWD/volumes/gateway:/cert:ro \
	--rm -d storjlabs/gateway-mt:${BUILD_NUMBER} run \
		--server.address 0.0.0.0:20010 \
		--server.address-tls 0.0.0.0:20011 \
		--auth.base-url http://authservice:20000 \
		--auth.token super-secret \
		--domain-name gateway \
		--insecure-log-all \
		--cert-dir /cert \
		--insecure-disable-tls=false \
		--s3compatibility.fully-compatible-listing \
		--s3compatibility.upload-part-copy.enable
