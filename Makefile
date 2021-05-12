## The repository where the container image will be pushed to.
IMAGE := ghcr.io/plexsystems/konstraint

#
##@ Development
#

.PHONY: build
build: ## Builds the binary. It will be placed into the build directory.
	go build -o build/konstraint

.PHONY: test
test: ## Runs the unit tests.
	go test -v ./... -count=1

.PHONY: acceptance
acceptance: build ## Runs the acceptance tests.
	bats acceptance.bats

.PHONY: policy
policy: ## Runs the policy tests.
	conftest verify -p examples

.PHONY: update-static
update-static: build ## Updates the static assets in the repository.
	./build/konstraint create examples
	./build/konstraint create test/create --output test/create
	./build/konstraint doc examples --output examples/policies.md
	./build/konstraint doc examples --output test/doc/expected.md

#
##@ Releases
#

.PHONY: docker-build
docker-build: ## Builds the docker image. Can optionally pass in a version.
ifeq ($(version),)
	docker build -t konstraint:latest .
else
	docker build -t konstraint:latest -t konstraint:$(version) --build-arg KONSTRAINT_VER=$(version) .
endif

.PHONY: docker-push
docker-push: ## Pushes the docker image to the container registry.
	@test $(version)
	docker tag konstraint:latest $(IMAGE):$(version)
	docker tag konstraint:latest $(IMAGE):latest
	docker push $(IMAGE):$(version)
	docker push $(IMAGE):latest

.PHONY: release
release: ## Builds the binaries for each OS and creates the checksums.
	@test $(version)
	GOOS=darwin GOARCH=amd64 go build -o build/konstraint-darwin-amd64 -ldflags="-X 'github.com/plexsystems/konstraint/internal/commands.version=$(version)'"
	GOOS=windows GOARCH=amd64 go build -o build/konstraint-windows-amd64.exe -ldflags="-X 'github.com/plexsystems/konstraint/internal/commands.version=$(version)'"
	GOOS=linux GOARCH=amd64 go build -o build/konstraint-linux-amd64 -ldflags="-X 'github.com/plexsystems/konstraint/internal/commands.version=$(version)'"
	docker run --rm -v $(shell pwd):/konstraint alpine:3 /bin/ash -c 'cd /konstraint/build && sha256sum konstraint-* > checksums.txt'

help:
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m\033[0m\n"} /^[$$()% a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)
