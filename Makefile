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
	conftest verify -p examples -d examples/test-data

.PHONY: update-static
update-static: build ## Updates the static assets in the repository.
	./build/konstraint create examples
	./build/konstraint create test/create --output test/create
	./build/konstraint doc examples --output examples/policies.md
	./build/konstraint doc examples --output test/doc/expected.md

.PHONY: fmt
fmt: ## Ensures consistent formatting on policy tests.
	conftest fmt examples

help:
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m\033[0m\n"} /^[$$()% a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)
