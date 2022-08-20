.PHONY: all
all: prereqs build

.PHONY: tidy
tidy:
	go mod tidy

.PHONY: fmt
fmt:
	go fmt ./...

.PHONY: generate
generate:
	go generate ./...

.PHONY: test
test:
	go test ./...

.PHONY: prereqs
prereqs: tidy fmt generate test

.PHONY: build
build:
	go build cmd/certforgot/main.go -o bin/certforgot

.PHONY: release
release:
	go run github.com/goreleaser/gorelease --snapshot