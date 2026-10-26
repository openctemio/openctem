### Removed: the admin-cli image is no longer published
- `ghcr.io/openctemio/admin-cli` held only `bootstrap-admin`, which the API image already ships as `/app/bootstrap-admin`. Run it from the API image instead: `docker compose run --rm bootstrap-admin ...` with Docker Compose, or a Job using the `openctem-api` image with command `/app/bootstrap-admin` on Kubernetes.
- Air-gapped installs: the image kit, the mirror list, the Harbor replication rule and the signature-verification policy template no longer include `admin-cli`.
