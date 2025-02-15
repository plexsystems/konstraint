#
##@ Development
#

.PHONY: build
build: ## Builds the binary. It will be placed into the build directory.
	go build -o build/konstraint

.PHONY: test
test: ## Runs the unit tests.
	go test -v ./... -count=1

.PHONY: lint
lint: ## Runs the go linters.
	golangci-lint run

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

.PHONY: fmt
fmt: ## Ensures consistent formatting on policy tests.
	conftest fmt examples

#
##@ Releases
#

.PHONY: release
release: ## Builds the binaries for each OS and creates the checksums.
	@test $(version)
	GOOS=darwin GOARCH=amd64 go build -o build/konstraint-darwin-amd64 -ldflags="-s -w -X 'github.com/plexsystems/konstraint/internal/commands.version=$(version)'"
	GOOS=darwin GOARCH=arm64 go build -o build/konstraint-darwin-arm64 -ldflags="-s -w -X 'github.com/plexsystems/konstraint/internal/commands.version=$(version)'"
	GOOS=windows GOARCH=amd64 go build -o build/konstraint-windows-amd64.exe -ldflags="-s -w -X 'github.com/plexsystems/konstraint/internal/commands.version=$(version)'"
	GOOS=linux GOARCH=amd64 go build -o build/konstraint-linux-amd64 -ldflags="-s -w -X 'github.com/plexsystems/konstraint/internal/commands.version=$(version)'"
	GOOS=linux GOARCH=arm64 go build -o build/konstraint-linux-arm64 -ldflags="-s -w -X 'github.com/plexsystems/konstraint/internal/commands.version=$(version)'"
	docker run --user $(shell id -u):$(shell id -g) --rm -v $(shell pwd):/konstraint alpine:3 /bin/ash -c 'cd /konstraint/build && sha256sum konstraint-* > checksums.txt'

help:
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m\033[0m\n"} /^[$$()% a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)
