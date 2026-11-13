### Fixed: generate-in-docker reads the contract from server/

- `make generate-docker` (`scripts/generate-in-docker.sh`) still read the OpenAPI spec from the old `api/` layout after the backend directory rename, so building the web or console image from a source checkout failed. It now reads `server/api/openapi/swagger.yaml`.
- CI now refuses a checkout mount path that names the old directory (the old directory under the checkout mount) and checks that every path `generate-in-docker.sh` reads exists in the tree.
- Source-checkout installs that bind-mount the gateway configuration: the directory is now `server/deploy/gateway`; change the mount and recreate the gateway container (see `server/docs/deployment/docker.md`).
- `make swagger` post-processed the spec with `perl`, which the golang alpine image `generate-in-docker.sh` uses does not have, so contract generation failed there. The step is now `server/scripts/stable-swagger-names.sh` (plain `sed`), shared by the Makefile and `server/Dockerfile`. CI generates the spec in that image with the same packages.
- Docs: server/docs/deployment/docker.md
