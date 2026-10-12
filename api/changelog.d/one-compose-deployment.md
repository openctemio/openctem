### Removed: the API-only and web-only production Compose files

- `api/docker-compose.prod.yml`, `web/docker-compose.prod.yml`,
  `web/docker-compose.prod-simple.yml` and `web/nginx/` are removed. The API-only
  file could not start in production (it disabled Redis TLS, which production
  refuses), and three partial production layouts drifted from the supported one.
- **Upgrade note:** deploy with `api/deploy/docker-compose.yml` (the whole stack
  behind one HTTPS port), the all-in-one image, or the Helm chart.
