.PHONY: build
build:
	go build -o build/konstraint

.PHONY: test
test:
	go test -v ./... -count=1

.PHONY: release
release:
	GOOS=darwin GOARCH=amd64 go build -o build/konstraint-darwin-amd64
	GOOS=windows GOARCH=amd64 go build -o build/konstraint-windows-amd64
	GOOS=linux GOARCH=amd64 go build -o build/konstraint-linux-amd64
