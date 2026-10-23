### Added: preview and validate an automation draft

- `POST /api/v1/workflows/{id}/preview` runs a draft (from the body, or the saved one) against the latest 1 to 100 subjects that the caller may read. It uses the read-only simulate evaluator and returns per-step counts and what the draft would send. Nothing is stored or sent. Limited to one call per 10 seconds per user.
- `POST /api/v1/workflows/{id}/validate` returns blocking problems (unsupported type, graph error, invalid condition or trigger options, missing setting, missing integration, a permission the caller lacks) and warnings (unknown condition field, not simulated since the last edit). Limited to 10 calls per 10 seconds per user.
