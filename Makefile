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
	GOOS=darwin GOARCH=amd64 go build -o build/konstraint-darwin-amd64
	GOOS=windows GOARCH=amd64 go build -o build/konstraint-windows-amd64
	GOOS=linux GOARCH=amd64 go build -o build/konstraint-linux-amd64

.PHONY: update-static
update-static: build
	./build/konstraint create examples
	./build/konstraint create examples --output test/create
	./build/konstraint doc examples --output examples/policies.md
	./build/konstraint doc examples --output test/doc/expected.md
