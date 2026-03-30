.PHONY: build test lint package deploy local-run clean vet

VERSION ?= dev
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
DATE    ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS  = -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)

# Build the Lambda bootstrap binary (Linux ARM64).
build:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags '$(LDFLAGS)' -o bootstrap ./cmd/checker

# Run all tests with race detector.
test:
	go test -race -coverprofile=coverage.out -covermode=atomic ./...

# Run linter.
lint:
	golangci-lint run ./...

# Run go vet.
vet:
	go vet ./...

# Package the Lambda function as a zip.
package: build
	zip -j function.zip bootstrap

# Deploy via Terraform.
deploy:
	cd terraform && terraform apply

# Build and run locally (for development).
local-run:
	go run -ldflags '$(LDFLAGS)' ./cmd/checker

# Remove build artifacts.
clean:
	rm -f bootstrap function.zip coverage.out
	rm -rf dist/
