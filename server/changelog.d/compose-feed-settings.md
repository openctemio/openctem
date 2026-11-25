### Fixed: Docker Compose passes the vulnerability feed settings, and the installer lists the override file and names the feed mode

- The `api` service now passes `VULNFEED_BASE_URL`, `VULNFEED_MIRRORS`, `VULNFEED_BUNDLE_DIR`, `VULNFEED_ROOT_KEY_ID`, `OPENCTEM_HTTPSEC_FEED_PROXY`, `OPENCTEM_HTTPSEC_FEED_NO_PROXY` and `OPENCTEM_HTTPSEC_ALLOW_PRIVATE_CIDRS` from `.env` (empty by default, so nothing changes when they are unset). Before, a value set in `.env` never reached the API. `VULNFEED_BUNDLE_DIR` still needs a read-only volume in an extra compose file.
- `install.sh` adds `docker-compose.override.yml` to the end of `COMPOSE_FILE` when the file exists next to it (new install and rerun); Compose ignores that file once `COMPOSE_FILE` is set. A missing file is never listed.
- The installer summary prints the vulnerability feed mode and the outbound access it needs, and says when the bundled sensor was left out because the host is an IP address.
- Docs: https://docs.openctem.io/operations/vulnerability-feed-setup/
