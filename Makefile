VERSION := $(shell git describe --tags)
LDFLAGS=-ldflags "-s -w -X=main.version=$(VERSION)"

GOPATH=$(shell go env GOPATH)
GOBIN=$(GOPATH)/bin
GOSRC=$(GOPATH)/src

u := $(if $(update),-u)

$(GOBIN)/wire:
	GO111MODULE=off go get github.com/google/wire/cmd/wire

.PHONY: wire
wire: $(GOBIN)/wire
	wire gen ./...

.PHONY: deps
deps:
	go get ${u} -d
	go mod tidy

$(GOBIN)/golangci-lint:
	curl -sfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh| sh -s -- -b $(GOBIN) v1.21.0

.PHONY: test
test:
	go test -v -short ./...

integration/testdata/fixtures/*.tar.gz:
	git clone https://github.com/aquasecurity/trivy-test-images.git integration/testdata/fixtures

.PHONY: test-integration
test-integration: integration/testdata/fixtures/*.tar.gz
	go test -v -tags=integration ./integration/...

.PHONY: lint
lint: $(GOBIN)/golangci-lint
	$(GOBIN)/golangci-lint run

.PHONY: fmt
fmt:
	find ./ -name "*.proto" | xargs clang-format -i

.PHONY: build
build:
	go build $(LDFLAGS) ./cmd/trivy

.PHONY: protoc
protoc:
	protoc --proto_path=$(GOSRC):. --twirp_out=. --go_out=. ./rpc/detector/service.proto

.PHONY: install
install:
	go install $(LDFLAGS) ./cmd/trivy

.PHONY: clean
clean:
	rm -rf integration/testdata/fixtures/
