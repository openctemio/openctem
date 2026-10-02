# OpenCTEM monorepo — thin root targets that delegate to api/ (make) and web/ (npm).
# Component-specific targets stay in api/Makefile and web/package.json.

.PHONY: help setup hooks dev-api dev-web build test lint check api-types allinone api-% web-%

help: ## Show this help
	@grep -hE '^[a-zA-Z_%-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  %-14s %s\n",$$1,$$2}'

setup: hooks ## Install dependencies for both components
	cd api && GOWORK=off go mod download
	cd web && npm ci

hooks: ## Use the repository's git hooks (.githooks)
	git config core.hooksPath .githooks

dev-api: ## Run the API with hot reload (air)
	$(MAKE) -C api run

dev-web: ## Run the web console (next dev)
	cd web && npm run dev

build: ## Build both components
	cd api && GOWORK=off go build ./...
	cd web && npm run build

test: ## Unit tests for both components
	cd api && GOWORK=off go test ./...
	cd web && npm test -- --run

lint: ## Lint both components (api: what CI gates on)
	$(MAKE) -C api lint-ci
	cd web && npm run lint && npm run type-check

api-types: ## Regenerate web wire types from api/api/openapi/swagger.yaml
	cd web && npm run generate:api-types

check: ## The contract checks CI runs on every PR
	bash api/scripts/check-openapi.sh
	cd web && npm run check:api-types

api-%: ## Run any api/Makefile target, e.g. make api-swagger
	$(MAKE) -C api $*

web-%: ## Run any web npm script, e.g. make web-format
	cd web && npm run $*

allinone: ## Build openctem-api, openctem-web and the all-in-one image locally (:local)
	docker build -t openctem-api:local --target production api
	docker build -t openctem-web:local web
	docker buildx build --load -t openctem:local --build-context gateway=api/deploy/gateway \
	  --build-arg API_IMAGE=openctem-api:local --build-arg WEB_IMAGE=openctem-web:local deploy/allinone
