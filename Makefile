# Setting SHELL to bash allows bash commands to be executed by recipes.
# Options are set to exit when a recipe line exits non-zero or a piped command fails.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

# GO_VERSION is the go directive in go.mod. Every recipe runs with exactly that toolchain, which is the
# one CI installs through go-version-file, so a newer local Go cannot change what the checks see.
# golangci-lint analyses the standard library of the toolchain in use, and a toolchain newer than the
# linter understands makes it crash rather than report a finding.
GO_VERSION := $(shell awk '$$1 == "go" && $$2 ~ /^[0-9]/ { print $$2; exit }' go.mod)
export GOTOOLCHAIN := go$(GO_VERSION)

CMP_TEST_SUITE_DIR := test/integration/cmp-test-suite/testdata/cmp-test-suite
CMP_TEST_SUITE_COMMIT := d35c9de4516924b0a9a96176b3c8692660e57a8c

# The Insta Certifier CMP clients are proprietary. CERTIFIER_CLIENTS_DIR is a local directory that holds
# them, laid out as test/integration/certifier/Dockerfile describes.
CERTIFIER_CLIENT_IMAGE ?= go-pkicmp-certifier-clients
CERTIFIER_CLIENTS_DIR ?=

.PHONY: all
all: test

##@ General

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-32s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

.PHONY: fmt
fmt: ## Format the Go sources.
	go fmt ./...

.PHONY: fmt-check
fmt-check: ## Fail when a tracked Go file is not gofmt formatted.
	@files=$$(git ls-files '*.go'); \
	if [ -z "$$files" ]; then echo "no Go files are tracked"; exit 1; fi; \
	unformatted=$$(gofmt -l $$files); \
	if [ -n "$$unformatted" ]; then echo "not gofmt formatted:"; echo "$$unformatted"; exit 1; fi

.PHONY: vet
vet: ## Run go vet, including the integration tests.
	go vet ./...
	go vet -tags integration ./test/...

.PHONY: tidy-check
tidy-check: ## Fail when go.mod or go.sum is not tidy.
	go mod tidy -diff

.PHONY: fix
fix: ## Modernize code to use newer Go APIs.
	go fix ./...

.PHONY: test
test: vet ## Run the unit tests under the race detector.
	go test -race -count=1 ./...

# FUZZTIME bounds each fuzz target. Raise it to hunt for new inputs locally, for example
# make fuzz FUZZTIME=10m. go test fuzzes one target per invocation, so the targets run in turn.
FUZZTIME ?= 30s
# Minimization of newly interesting inputs stalls the workers for seconds at a time. A worker still
# busy when FUZZTIME expires makes Go report the run as failed with "context deadline exceeded"
# (golang/go#75804), so the bounded runs disable it. Set a duration to minimize crashers locally.
FUZZMINIMIZETIME ?= 0

.PHONY: fuzz
fuzz: ## Fuzz every target in pkicmp for FUZZTIME each. Failing inputs are saved under testdata.
	@targets=$$(go test -list '^Fuzz' ./pkicmp/ | awk '/^Fuzz/ {print $$1}'); \
	if [ -z "$$targets" ]; then echo "no fuzz targets found in ./pkicmp/"; exit 1; fi; \
	for target in $$targets; do \
		echo "fuzzing $$target for $(FUZZTIME)"; \
		go test -run "^$$" -fuzz "^$$target$$" -fuzztime "$(FUZZTIME)" -fuzzminimizetime "$(FUZZMINIMIZETIME)" ./pkicmp/; \
	done

##@ Integration

.PHONY: test-integration
test-integration: test-integration-ejbca test-integration-openssl test-integration-cmp-test-suite test-integration-ncm test-integration-certifier ## Run all integration tests. The NCM and Insta Certifier client tests skip without their setup.

.PHONY: test-integration-ejbca
test-integration-ejbca: ## Run the client against EJBCA. Needs make setup-ejbca.
	go test -v -count=1 -tags integration ./test/integration/ejbca

.PHONY: test-integration-openssl
test-integration-openssl: ## Run the client and server against OpenSSL. Needs OpenSSL 3.2 or newer.
	go test -v -count=1 -tags integration ./test/integration/openssl

.PHONY: test-integration-cmp-test-suite
test-integration-cmp-test-suite: ## Run the server against the Siemens CMP test suite. Needs make setup-cmp-test-suite.
	go test -v -count=1 -tags integration -timeout 15m ./test/integration/cmp-test-suite

.PHONY: test-integration-ncm
test-integration-ncm: ## Run the client against a Nokia NCM instance described by the NCM_CMP_* variables.
	go test -v -count=1 -tags integration -timeout 20m ./test/integration/ncm

.PHONY: test-integration-certifier
test-integration-certifier: ## Run the server against the Insta Certifier CMP clients. Needs make setup-certifier-clients.
	CERTIFIER_CLIENT_IMAGE=$(CERTIFIER_CLIENT_IMAGE) go test -v -count=1 -tags integration -timeout 30m ./test/integration/certifier

.PHONY: setup
setup: setup-ejbca setup-cmp-test-suite ## Set up all integration environments.

.PHONY: setup-ejbca
setup-ejbca: ## Start and configure the EJBCA container. Needs Docker.
	docker compose -f test/integration/ejbca/docker-compose.yml up -d
	bash test/integration/ejbca/setup.sh

.PHONY: setup-certifier-clients
setup-certifier-clients: ## Build the Insta Certifier client image from CERTIFIER_CLIENTS_DIR. Needs Docker.
	@test -n "$(CERTIFIER_CLIENTS_DIR)" || { echo "error: set CERTIFIER_CLIENTS_DIR to the directory that holds bin/cmpclient"; exit 1; }
	docker build --platform linux/amd64 -t $(CERTIFIER_CLIENT_IMAGE) -f test/integration/certifier/Dockerfile $(CERTIFIER_CLIENTS_DIR)

.PHONY: setup-cmp-test-suite
setup-cmp-test-suite: _clone-cmp-test-suite _sync-cmp-test-suite ## Clone the pinned CMP test suite and install its dependencies. Needs uv.

.PHONY: teardown
teardown: teardown-ejbca ## Tear down all integration environments.

.PHONY: teardown-ejbca
teardown-ejbca: ## Stop and remove the EJBCA container.
	docker compose -f test/integration/ejbca/docker-compose.yml down

.PHONY: clean
clean: ## Remove the cloned CMP test suite.
	rm -rf $(CMP_TEST_SUITE_DIR)

.PHONY: _clone-cmp-test-suite
_clone-cmp-test-suite:
	@if [ ! -d "$(CMP_TEST_SUITE_DIR)" ]; then \
		git clone --depth 1 https://github.com/siemens/cmp-test-suite.git $(CMP_TEST_SUITE_DIR) && \
		cd $(CMP_TEST_SUITE_DIR) && git fetch --depth 1 origin $(CMP_TEST_SUITE_COMMIT) && git checkout $(CMP_TEST_SUITE_COMMIT); \
	fi

.PHONY: _sync-cmp-test-suite
_sync-cmp-test-suite:
	cd $(CMP_TEST_SUITE_DIR) && uv sync --extra pq

##@ Documentation

.PHONY: docs
docs: ## Serve the package documentation locally with pkgsite.
	# https://github.com/golang/pkgsite
	pkgsite -http localhost:9430 -open .

##@ Release

# VERSION names the release tag, for example v0.2.0. Every artifact is named after it.
VERSION ?=
# Artifacts without a release, such as the routine SBOM run, are named after the commit instead.
SBOM_VERSION := $(if $(VERSION),$(VERSION),$(shell git rev-parse --short HEAD))
SOURCE_ZIP = dist/go-pki-cmp-$(VERSION)-source.zip
SOURCE_TAR_GZ = dist/go-pki-cmp-$(VERSION)-source.tar.gz
SBOM_FILE = dist/go-pki-cmp-$(SBOM_VERSION)-sbom.cdx.json
RELEASE_CHECKSUMS = dist/go-pki-cmp-$(VERSION)_SHA256SUMS.txt
# RELEASE_CHECK_DIR holds the exported tree and the consumer module of a release check and must not exist yet.
# Empty selects a new directory under the system temporary directory, which the operating system cleans up.
RELEASE_CHECK_DIR ?=

.PHONY: require-version
require-version:
	@test -n "$(VERSION)" || { echo "Set VERSION, for example VERSION=v0.2.0" >&2; exit 1; }

.PHONY: release-check
release-check: ## Build, vet and test an export of HEAD in a new directory and import it from a separate module. Set VERSION to check the release notes heading.
	@if grep -q '^replace ' go.mod; then echo "error: go.mod has a replace directive"; exit 1; fi
	@if [ -n "$(VERSION)" ]; then \
		grep -q "^## $(VERSION) - " RELEASE_NOTES.md || { echo "error: RELEASE_NOTES.md has no heading for $(VERSION)"; exit 1; }; \
		if grep -q '^## v.* - TBD$$' RELEASE_NOTES.md; then echo "error: RELEASE_NOTES.md still has a section dated TBD"; exit 1; fi; \
	fi
	@export="$(RELEASE_CHECK_DIR)"; \
	if [ -z "$$export" ]; then \
		tmp="$${TMPDIR:-/tmp}"; export="$$(mktemp -d "$${tmp%/}/go-pki-cmp-release-check.XXXXXX")"; \
	elif [ -e "$$export" ]; then \
		echo "error: $$export exists, move it aside first"; exit 1; \
	fi; \
	echo "release check directory: $$export"; \
	mkdir -p "$$export/export" "$$export/consumer"; \
	git archive --format=tar HEAD | tar -x -C "$$export/export"; \
	cd "$$export/export" && go mod verify && go build ./... && go vet ./... && go test -count=1 ./...; \
	cd "$$export/consumer" && printf 'module example.com/consumer\n\ngo %s\n\nrequire github.com/misiektoja/go-pki-cmp v0.0.0\n\nreplace github.com/misiektoja/go-pki-cmp => ../export\n' "$(GO_VERSION)" > go.mod; \
	printf 'package main\n\nimport (\n\t"log"\n\n\t"github.com/misiektoja/go-pki-cmp/client"\n\t"github.com/misiektoja/go-pki-cmp/pkicmp"\n\t"github.com/misiektoja/go-pki-cmp/server"\n)\n\nfunc main() {\n\t_, err := pkicmp.NewMACCredentials([]byte("release-check"))\n\tlog.Println(client.NewClient("http://localhost/cmp") != nil, server.NewCAServer(nil, server.LightweightPolicy()).Err(), err)\n}\n' > main.go; \
	go mod tidy && go build ./... && go run .; \
	echo "release check passed for $$(git -C "$(CURDIR)" rev-parse --short HEAD)"

.PHONY: release-body
release-body: require-version ## Extract the RELEASE_NOTES.md section of VERSION into dist/release-body.md.
	@mkdir -p dist
	@awk -v want="## $(VERSION) - " 'index($$0, want) == 1 { found = 1; next } found && /^## / { exit } found { print }' RELEASE_NOTES.md | sed '/./,$$!d' > dist/release-body.md
	@grep -q '[^[:space:]]' dist/release-body.md || { echo "error: RELEASE_NOTES.md has no section for $(VERSION)" >&2; exit 1; }
	@echo "Wrote dist/release-body.md"

.PHONY: sbom
sbom: cyclonedx-gomod ## Generate a CycloneDX software bill of materials for the module. Set VERSION for a release.
	mkdir -p dist
	"$(CYCLONEDX_GOMOD)" mod -licenses -json -output "$(SBOM_FILE)" .
	@echo "Wrote $(SBOM_FILE)"

.PHONY: release-source-archives
release-source-archives: require-version ## Archive the complete tagged source tree as ZIP and tar. Set VERSION.
	mkdir -p dist
	git archive --format=zip --output "$(SOURCE_ZIP)" "$(VERSION)"
	git archive --format=tar.gz --output "$(SOURCE_TAR_GZ)" "$(VERSION)"

.PHONY: release-checksums
release-checksums: release-source-archives ## Write SHA-256 checksums for the source archives and the SBOM. Set VERSION.
	@test -f "$(SBOM_FILE)" || { echo "Run sbom with the same VERSION first, $(SBOM_FILE) is missing" >&2; exit 1; }
	cd dist && shasum -a 256 "$(notdir $(SBOM_FILE))" "$(notdir $(SOURCE_ZIP))" "$(notdir $(SOURCE_TAR_GZ))" | tee "$(notdir $(RELEASE_CHECKSUMS))"

##@ Checks

.PHONY: lint
lint: golangci-lint ## Run golangci-lint, including the integration tests.
	"$(GOLANGCI_LINT)" run

.PHONY: lint-fix
lint-fix: golangci-lint ## Run golangci-lint and apply the fixes it offers.
	"$(GOLANGCI_LINT)" run --fix

.PHONY: lint-config
lint-config: golangci-lint ## Verify the golangci-lint configuration.
	"$(GOLANGCI_LINT)" config verify

.PHONY: actionlint
actionlint: actionlint-tool ## Lint the GitHub Actions workflows.
	"$(ACTIONLINT)"

.PHONY: govulncheck
govulncheck: govulncheck-tool ## Report known vulnerabilities that reach the module or its dependencies.
	"$(GOVULNCHECK)" ./...

# GITLEAKS_LOG_OPTS selects the history the commit scan walks.
GITLEAKS_LOG_OPTS ?= --full-history --all
# Untracked directories that hold local state, tool binaries, integration test output and the cloned
# CMP test suite. .gitleaks.toml excludes them from the working tree scan.
GITLEAKS_EXCLUDED := local .cache bin dist test/integration/cmp-test-suite/reports $(CMP_TEST_SUITE_DIR)

.PHONY: gitleaks
gitleaks: gitleaks-tool ## Scan the working tree and the commit history for leaked credentials.
# Excluded paths must not contain tracked files.
	@test -z "$$(git ls-files $(GITLEAKS_EXCLUDED) 'test/integration/ejbca/testdata/*.pem' 'test/integration/ejbca/testdata/*.p12')" || { echo "error: tracked files are excluded from the gitleaks scan by .gitleaks.toml"; exit 1; }
	"$(GITLEAKS)" dir . --config .gitleaks.toml --redact --no-banner
	"$(GITLEAKS)" git . --config .gitleaks.toml --redact --no-banner --log-opts="$(GITLEAKS_LOG_OPTS)"

##@ Dependencies

## Location to install dependencies to
LOCALBIN ?= $(shell pwd)/bin
$(LOCALBIN):
	mkdir -p "$(LOCALBIN)"

## Tool Binaries
GOLANGCI_LINT ?= $(LOCALBIN)/golangci-lint
GOVULNCHECK ?= $(LOCALBIN)/govulncheck
GITLEAKS ?= $(LOCALBIN)/gitleaks
ACTIONLINT ?= $(LOCALBIN)/actionlint
CYCLONEDX_GOMOD ?= $(LOCALBIN)/cyclonedx-gomod

## Tool Versions
GOLANGCI_LINT_VERSION ?= v2.14.0
GOVULNCHECK_VERSION ?= v1.7.0
GITLEAKS_VERSION ?= v8.30.1
ACTIONLINT_VERSION ?= v1.7.12
CYCLONEDX_GOMOD_VERSION ?= v1.11.0

.PHONY: golangci-lint
golangci-lint: | $(LOCALBIN) ## Download golangci-lint locally if necessary.
	$(call go-install-tool,$(GOLANGCI_LINT),github.com/golangci/golangci-lint/v2/cmd/golangci-lint,$(GOLANGCI_LINT_VERSION))

.PHONY: govulncheck-tool
govulncheck-tool: | $(LOCALBIN) ## Download govulncheck locally if necessary.
	$(call go-install-tool,$(GOVULNCHECK),golang.org/x/vuln/cmd/govulncheck,$(GOVULNCHECK_VERSION))

.PHONY: gitleaks-tool
gitleaks-tool: | $(LOCALBIN) ## Download gitleaks locally if necessary.
	$(call go-install-tool,$(GITLEAKS),github.com/zricethezav/gitleaks/v8,$(GITLEAKS_VERSION))

.PHONY: actionlint-tool
actionlint-tool: | $(LOCALBIN) ## Download actionlint locally if necessary.
	$(call go-install-tool,$(ACTIONLINT),github.com/rhysd/actionlint/cmd/actionlint,$(ACTIONLINT_VERSION))

.PHONY: cyclonedx-gomod
cyclonedx-gomod: | $(LOCALBIN) ## Download cyclonedx-gomod locally if necessary.
	$(call go-install-tool,$(CYCLONEDX_GOMOD),github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod,$(CYCLONEDX_GOMOD_VERSION))

# go-install-tool installs a package at a pinned version under a versioned directory and points the
# unversioned tool path at it, so a version bump installs the new tool instead of keeping the old one.
# $1 - tool path, $2 - package path, $3 - version
define go-install-tool
@dir="$(LOCALBIN)/.tools/$(notdir $(1))@$(3)"; \
if [ ! -x "$$dir/$(notdir $(1))" ]; then \
	echo "Downloading $(2)@$(3)"; \
	mkdir -p "$$dir"; \
	GOBIN="$$dir" go install "$(2)@$(3)"; \
fi; \
ln -sfn "$$dir/$(notdir $(1))" "$(1)"
endef
