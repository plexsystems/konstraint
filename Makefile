.PHONY: build
build:
	go build -o build/konstraint

.PHONY: test
test:
	go test -v ./... -count=1

.PHONY: acceptance
acceptance: build
	bats acceptance.bats

.PHONY: release
release:
	@test $(version)
	GOOS=darwin GOARCH=amd64 go build -o build/konstraint-darwin-amd64 -ldflags="-X 'github.com/plexsystems/konstraint/internal/commands.version=$(version)'"
	GOOS=windows GOARCH=amd64 go build -o build/konstraint-windows-amd64 -ldflags="-X 'github.com/plexsystems/konstraint/internal/commands.version=$(version)'"
	GOOS=linux GOARCH=amd64 go build -o build/konstraint-linux-amd64 -ldflags="-X 'github.com/plexsystems/konstraint/internal/commands.version=$(version)'"

.PHONY: update-static
update-static: build
	./build/konstraint create examples
	./build/konstraint create examples --output test/create
	./build/konstraint doc examples --output examples/policies.md
	./build/konstraint doc examples --output test/doc/expected.md
