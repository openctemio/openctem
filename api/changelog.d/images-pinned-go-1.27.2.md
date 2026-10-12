### Security: every image builds on digest-pinned bases with Go 1.27.2

- All Dockerfiles (API, web, migrations, seed, admin-cli, gateway, all-in-one)
  pin their base images by digest in the `FROM` line, where Dependabot keeps
  them current. The gateway and all-in-one images took Go and Alpine from
  `ARG` defaults that Dependabot never updated (they were still on Go 1.26.9).
- Go 1.27.0 to 1.27.2: the binaries built with 1.27.0 (caddy, migrate,
  bootstrap-admin, the API) carried standard-library advisories fixed in
  1.27.2.
- admin-cli moves from distroless Debian 12 to Debian 13, like the API image.

### Fixed: a refused legacy-name copy no longer stops a release

- The copy of `openctem-web` to the old `ghcr.io/openctemio/ui` name was
  refused by the registry, which failed the publish job. v0.9.0 therefore has
  no all-in-one image, no cosign signatures, no SBOM attestations and no
  Docker Hub mirror. The copy is now best effort and warns.
- Release images carry `org.opencontainers.image.revision`, `created`,
  `title`, `description` and `licenses` labels. The gateway image has a
  `HEALTHCHECK`, and the image guard no longer exempts it from the non-root
  check (it runs as uid 1000).
