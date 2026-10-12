### Fixed: the API images serve the OpenAPI spec again

- `openctem-api` and the all-in-one image generate the OpenAPI spec during the
  image build (it is no longer committed), so `GET /openapi.yaml` and `/docs`
  work on image installs instead of answering 404 / an empty page.
- The spec declares the project licence (GPL-3.0-only) instead of MIT.
