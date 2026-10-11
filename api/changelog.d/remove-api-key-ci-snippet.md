### Removed: the API-key CI snippet of a scan

- `GET /api/v1/scans/{id}/ci-snippet` is removed. It generated GitHub Actions,
  GitLab CI and Jenkins files that stored a long-lived API key in CI and
  triggered a platform scan; no console page called it. CI jobs report with
  their provider's OIDC identity through a CI trust configuration
  (RFC-051), and the CI/CD page gives the pipeline snippet for each provider.
