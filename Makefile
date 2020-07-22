.PHONY: build
build:
	go build

.PHONY: test
test:
	go test -v ./... -count=1

.PHONY: acceptance
test:
	bats acceptance.bats

.PHONY: release
release:
	GOOS=darwin GOARCH=amd64 go build -o konstraint-darwin-amd64
	GOOS=windows GOARCH=amd64 go build -o konstraint-windows-amd64
	GOOS=linux GOARCH=amd64 go build -o konstraint-linux-amd64
