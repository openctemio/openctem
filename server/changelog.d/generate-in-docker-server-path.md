### Fixed: generate-in-docker reads the contract from server/

- `make generate-docker` (`scripts/generate-in-docker.sh`) still read the OpenAPI spec from the old `api/` layout after the backend directory rename, so building the web or console image from a source checkout failed. It now reads `server/api/openapi/swagger.yaml`.
- CI now refuses a checkout mount path that names the old directory (`/src/api`) and checks that every path `generate-in-docker.sh` reads exists in the tree.
- Source-checkout installs that bind-mount the gateway configuration: the directory is now `server/deploy/gateway`; change the mount and recreate the gateway container (see `server/docs/deployment/docker.md`).
