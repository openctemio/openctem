# OpenCTEM monorepo — thin root targets that delegate to api/ (make) and web/ (npm).
# Component-specific targets stay in api/Makefile and web/package.json.

.PHONY: help setup hooks generate generate-api generate-web generate-docker dev-api dev-web build test lint check api-types allinone api-% web-%

help: ## Show this help
	@grep -hE '^[a-zA-Z_%-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  %-14s %s\n",$$1,$$2}'

setup: hooks ## Install dependencies for both components, then generate the contract files
	cd api && GOWORK=off go mod download
	cd web && npm ci
	$(MAKE) generate

hooks: ## Use the repository's git hooks (.githooks)
	git config core.hooksPath .githooks

# The contract files are generated, never committed (pull requests cannot
# conflict on them): the OpenAPI spec, the route manifest and the web route
# permission map come from the Go source, the web API types from the spec.
# CI and the image builds run `make generate` first; run it locally after
# pulling or after changing a handler, a route or its gate.
generate: generate-api generate-web ## Generate every contract file (needs Go and Node)

generate-api: ## Generate the spec, route manifest and route permission map (needs Go)
	@command -v go >/dev/null || { echo "make generate-api needs Go (or run: make generate-docker)" >&2; exit 1; }
	$(MAKE) -C api contract

generate-web: ## Generate the web API types from the spec (needs Node and web/node_modules)
	@command -v node >/dev/null || { echo "make generate-web needs Node (or run: make generate-docker)" >&2; exit 1; }
	@test -d web/node_modules || { echo "web/node_modules is missing: run npm ci in web/ first" >&2; exit 1; }
	cd web && npm run generate:api-types

generate-docker: ## Generate every contract file in containers (needs only Docker)
	bash scripts/generate-in-docker.sh

dev-api: ## Run the API with hot reload (air)
	$(MAKE) -C api run

dev-web: ## Run the web console (next dev)
	cd web && npm run dev

build: generate ## Build both components
	cd api && GOWORK=off go build ./...
	cd web && npm run build

test: generate ## Unit tests for both components
	cd api && GOWORK=off go test ./...
	cd web && npm test -- --run

lint: generate ## Lint both components (api: what CI gates on)
	$(MAKE) -C api lint-ci
	cd web && npm run lint && npm run type-check

api-types: generate-web ## Regenerate the web wire types from the generated spec

check: generate ## The contract checks CI runs on every PR
	bash api/scripts/check-openapi.sh
	cd web && npm run type-check

api-%: ## Run any api/Makefile target, e.g. make api-swagger
	$(MAKE) -C api $*

web-%: ## Run any web npm script, e.g. make web-format
	cd web && npm run $*

allinone: generate ## Build openctem-api, openctem-web and the all-in-one image locally (:local)
	docker build -t openctem-api:local --target production api
	docker build -t openctem-web:local web
	docker buildx build --load -t openctem:local --build-context gateway=api/deploy/gateway \
	  --build-arg API_IMAGE=openctem-api:local --build-arg WEB_IMAGE=openctem-web:local deploy/allinone
