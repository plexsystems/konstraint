IMAGE := docker.pkg.github.com/plexsystems/konstraint

.PHONY: build
build:
	go build -o build/konstraint

.PHONY: test
test:
	go test -v ./... -count=1

.PHONY: acceptance
acceptance: build
	bats acceptance.bats

.PHONY: policy
policy:
	conftest verify -p examples

.PHONY: update-static
update-static: build
	./build/konstraint create examples
	./build/konstraint create test/create --output test/create
	./build/konstraint doc examples --output examples/policies.md
	./build/konstraint doc examples --output test/doc/expected.md

# A version is required when creating a release (make release version=0.6.0)
# Running this command without a version variable set will result in an error.
.PHONY: release
release:
	@test $(version)
	GOOS=darwin GOARCH=amd64 go build -o build/konstraint-darwin-amd64 -ldflags="-X 'github.com/plexsystems/konstraint/internal/commands.version=$(version)'"
	GOOS=windows GOARCH=amd64 go build -o build/konstraint-windows-amd64.exe -ldflags="-X 'github.com/plexsystems/konstraint/internal/commands.version=$(version)'"
	GOOS=linux GOARCH=amd64 go build -o build/konstraint-linux-amd64 -ldflags="-X 'github.com/plexsystems/konstraint/internal/commands.version=$(version)'"
	docker run --rm -v $(shell pwd):/konstraint alpine:3 /bin/ash -c 'cd /konstraint/build && sha256sum konstraint-* > checksums.txt'

.PHONY: docker-build
docker-build:
ifeq ($(version),) # this can't be indented because makefiles are picky
	docker build -t konstraint:latest .
else
	docker build -t konstraint:latest -t konstraint:$(version) --build-arg KONSTRAINT_VER=$(version) .
endif

# The version and the docker repository are required to use the docker-push target
.PHONY: docker-push
docker-push:
	@test $(DOCKER_REPO)
	@test $(version)
	docker tag konstraint:latest $(IMAGE):$(version)
	docker tag konstraint:latest $(IMAGE):latest
	docker push $(IMAGE):$(version)
	docker push $(IMAGE):latest
