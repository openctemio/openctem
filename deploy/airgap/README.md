# OpenCTEM image kit: private registries and air-gapped sites

Everything here works without the OpenCTEM source code. The release ships
this folder as `openctem-image-kit-<version>.tar.gz`, covered by the release's
signed `checksums-sha256.txt`. Guide: `api/docs/deployment/air-gapped.md`
(and "Air-gapped installs" on https://docs.openctem.io).

| Path | What it is for |
|---|---|
| `mirror-images.sh` | Copies the release images into your registry with their digests, cosign signatures and attestations, verifying them before and after. Sources: ghcr.io, a registry proxy of it (Nexus), a staging project, or the offline bundle. |
| `nexus/` | Nexus Repository 3 proxies: Docker proxy of ghcr.io, raw proxies of the GitHub release assets and API, Helm proxy of the chart repository, and a script that creates them through the REST API. |
| `harbor/` | Harbor projects, robot accounts and policies (`harbor-robot-account.md`), endpoint, replication and project API bodies. |
| `gitlab/.gitlab-ci.mirror.yml` | Scheduled CI job: discover a release, mirror it to staging, scan, promote to trusted, open a merge request pinning the digests. |
| `gitlab/.gitlab-ci.build.yml` | CI job that builds the images from the release archives (no source), scans, signs with your key and pushes. |
| `gitlab/Dockerfile.ci-tools` | The tools image both CI templates run in (oras, cosign, crane, trivy), downloads pinned by sha256. |
| `gitlab/scripts/` | The CI helpers: discover a release, fetch and verify release assets, scan, bump the deployment repository. |
| `image-kit/` | Dockerfiles that assemble each image from the release archives (COPY only, no RUN), `unpack.sh` to verify and unpack the archives for them. |
| `templates/` | Docker Compose `.env`, Helm values and Ansible variables for a private registry; Kyverno signature policy; egress proxy (Squid) and firewall (nftables) allowlists. |

Images of a release: `openctem-api`, `openctem-web`, `openctem-console`,
`openctem-gateway`, `migrations`, `seed`, `admin-cli`, and the all-in-one
`openctem`. Each is signed keyless by
`https://github.com/openctemio/openctem/.github/workflows/docker-publish.yml@refs/tags/<version>`
(issuer `https://token.actions.githubusercontent.com`). Release assets
(`checksums-sha256.txt`) are signed by `.../release.yml@refs/tags/<version>`.
