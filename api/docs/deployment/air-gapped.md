# Private registries and air-gapped installs

How to run OpenCTEM where clusters and hosts cannot pull from the internet:
images and release files reach your own registry (Harbor, Nexus, GitLab
Container Registry) and artifact store first, verified, and every install
pulls from there. Everything here works without the OpenCTEM source code. The
templates live in `deploy/airgap/` and ship with each release as
`openctem-image-kit-<version>.tar.gz`. The public guide (with architecture
diagrams per path) is "Air-gapped installs" on https://docs.openctem.io.

## What stays verifiable

| Artifact | Signed by (keyless, issuer `https://token.actions.githubusercontent.com`) | Check |
|---|---|---|
| Images (`openctem-api`, `-web`, `-console`, `-gateway`, `migrations`, `seed`, all-in-one `openctem`) | `https://github.com/openctemio/openctem/.github/workflows/docker-publish.yml@refs/tags/<version>`, plus SLSA provenance and an SPDX SBOM attestation | `cosign verify`, `cosign verify-attestation` |
| Release files (`checksums-sha256.txt` covers every archive and SBOM) | `.../release.yml@refs/tags/<version>`, plus SLSA provenance per archive | `cosign verify-blob`, `sha256sum -c`, `gh attestation verify` |
| Offline image bundle list (`openctem-images-<version>.txt`) | `.../docker-publish.yml@refs/tags/<version>` | `cosign verify-blob` |

Image signatures and attestations are stored with the OCI referrers **tag
schema** (ghcr.io has no referrers API): for an image with index digest
`sha256:abc…` the tag `sha256-abc…` holds an index of its signature,
provenance and SBOM attestation. Any registry that serves tags therefore
serves them too, and `cosign` finds them there. `oras cp -r` copies an image
together with them, preserving every digest; into a registry with the
referrers API (Harbor 2.8+) it stores them through that API, into one without
(Nexus) it keeps the tag schema.

Always pin the identity to the exact tag (`--certificate-identity
.../docker-publish.yml@refs/tags/v0.13.0`): an image signed for another
release, or by another workflow, fails.

## Choosing a path

| Path | Egress it needs | Keeps our signatures | Automation | Best for |
|---|---|---|---|---|
| **P0. Existing Nexus proxies** (Docker proxy of ghcr.io + raw proxy of the GitHub release files), CI job promotes into Harbor | none new: the Nexus proxies already reach the internet | yes | scheduled, hands-off | sites that already proxy packages through Nexus |
| A1. Harbor pulls from ghcr.io itself (replication or proxy cache) | Harbor to `ghcr.io`, `pkg-containers.githubusercontent.com` | through the promotion step | scheduled | Harbor-only sites |
| A2. CI mirror job on a runner with narrow egress | runner to the image source and release files | yes | scheduled, hands-off, merge request with new digests | GitLab sites without a Nexus proxy |
| A3. Offline bundle (manual transfer) | none on the inside | yes (verified offline) | manual per release | zero-egress sites |
| B. Build images from the release archives in your CI | release files only | no: new digests, sign with your own key | scheduled or manual | policies that require images built in-house |
| Mixed | as the parts | as the parts | | e.g. images through Nexus, archives by A3 |

### P0. Nexus Docker proxy and raw proxy (recommended with Nexus)

1. Create the repositories (`deploy/airgap/nexus/`, `create-repositories.sh`
   posts the JSON bodies to `/service/rest/v1/repositories/...`):
   - `ghcr-proxy`: Docker proxy, remote `https://ghcr.io`, Docker v2 only,
     anonymous upstream (the images are public), its own HTTPS connector
     port (or a reverse proxy in front), metadata max age 60 minutes, a
     negative cache of 1 minute (a release's signatures are attached minutes
     after its images; a longer negative cache would hide them). Docker
     clients need the "Docker Bearer Token Realm" active.
   - `openctem-hosted` (optional): Docker hosted repository as a destination,
     write policy `ALLOW` (with `ALLOW_ONCE` a second mirror run fails).
   - `github-openctemio`: raw proxy of `https://github.com/openctemio/`
     (release files; Nexus follows the redirect to
     `release-assets.githubusercontent.com`).
   - `github-api`: raw proxy of `https://api.github.com/` with short caching,
     for the mirror job's "latest release" lookup.
   - `helm-openctem`: Helm proxy of `https://openctemio.github.io/helm-charts`.
   Tested with Nexus Repository 3.70: through the proxy and in the hosted
   repository, `cosign verify` and `verify-attestation` (provenance, SBOM)
   pass; Nexus answers 404 on the referrers API and clients use the tag
   schema.
2. Check from inside:
   `cosign verify --certificate-identity https://github.com/openctemio/openctem/.github/workflows/docker-publish.yml@refs/tags/<v> --certificate-oidc-issuer https://token.actions.githubusercontent.com nexus.example.internal:8443/openctemio/openctem-api:<v>`.
3. Promote into Harbor with the CI mirror job (A2) using the Nexus proxy as
   `OPENCTEM_SOURCE_PREFIX` and the raw proxies as `RELEASES_BASE_URL` /
   `RELEASE_API_URL`: staging, Trivy, trusted, merge request.

### A1. Harbor egress exception

Harbor replication (`harbor/replication-rule-openctem.json`, exact repository
names, `v*` tags) or a proxy cache project fills `openctem-staging`. These
features do not carry our tag-schema signatures as Harbor signatures, so
promote to `openctem-trusted` with `mirror-images.sh`, which copies and
verifies them (`harbor/harbor-robot-account.md`).

Security of the egress exception:

| Threat | Mitigation |
|---|---|
| Malicious or compromised upstream image | identity-pinned cosign verification before promotion; Trivy gate; Kyverno in the cluster; exact repository names in the replication filter |
| Harbor used as an exfiltration path | egress only through the SNI-allowlist proxy (`templates/squid-egress-allowlist.conf`), firewall drop by default (`templates/nftables-egress-allowlist.nft`), proxy access log to the SIEM |
| Information leakage (what you run) | anonymous pulls of public images; nothing about your inventory leaves |
| Upstream outage | staging keeps the last good release; releases are pinned by digest |
| Vulnerability in Harbor itself | Harbor on its own host, patched; no cluster credentials on it; robot accounts scoped and expiring |
| MITM or DNS spoofing | TLS to ghcr.io; signatures and digests are verified independently of the transport |

### A2. CI mirror job

`deploy/airgap/gitlab/.gitlab-ci.mirror.yml` (scheduled; unprivileged runner):
discover the release, fetch the release's image kit (signed checksums
verified), `mirror-images.sh` to staging (verified at the source and in
staging), Trivy, promote to trusted (verified again), optional merge request
in your deployment repository pinning the digests
(`scripts/bump-deployment.sh`). Its tools image: `gitlab/Dockerfile.ci-tools`.

### A3. Offline bundle

Each production release attaches `openctem-image-<name>-<version>.oci.tar`
(the multi-arch index with its signature and attestations, as an OCI layout)
and `openctem-images-<version>.txt` (name, source reference, digest, archive
name and sha256) with its Sigstore bundle.

```bash
# On a connected workstation
gh release download v0.13.0 -R openctemio/openctem -p 'openctem-image-*' -p 'openctem-images-*' \
  -p 'openctem-image-kit-*' -p 'checksums-sha256.txt*'
cosign verify-blob openctem-images-v0.13.0.txt --bundle openctem-images-v0.13.0.txt.sigstore.json \
  --certificate-identity https://github.com/openctemio/openctem/.github/workflows/docker-publish.yml@refs/tags/v0.13.0 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
# Transfer the directory, then inside:
oras login registry.example.internal
./mirror-images.sh bundle ./bundle registry.example.internal/openctem-trusted --trusted-root trusted_root.json
```

### B. Build the images from the release archives

`deploy/airgap/image-kit/`: one Dockerfile per image that only copies the
released files onto a pinned base image, with the official images' users,
paths, healthchecks and entrypoints. `unpack.sh` verifies the archives (signed
checksums) and lays them out for the Dockerfiles. Without RUN steps they build
unprivileged (kaniko) and for arm64 on amd64 runners. The images get new
digests and no OpenCTEM signature: sign them with your key
(`gitlab/.gitlab-ci.build.yml`: fetch, build, index, Trivy, sign, promote) and
enforce that key in the cluster. The web and console images use a glibc Node.js
base (the archives carry glibc native modules).

## Verifying signatures without internet access

Keyless verification needs the Sigstore trusted root. Fetch it where you have
internet with any online `cosign verify` (it lands in
`~/.sigstore/root/tuf-repo-cdn.sigstore.dev/targets/trusted_root.json`,
verified through Sigstore's TUF repository), carry it in, and pass
`--offline --trusted-root trusted_root.json` (`mirror-images.sh` and
`unpack.sh` take `--trusted-root`). The signature bundles carry their
transparency-log inclusion proofs, so nothing is looked up online. Do not take
the trusted root from the same medium as the artifacts it verifies.

## Pointing installs at the registry

- Docker Compose: `templates/.env.private-registry.example` (`API_IMAGE`,
  `UI_IMAGE`, `CONSOLE_IMAGE`, `GATEWAY_IMAGE`, `MIGRATIONS_IMAGE`,
  `POSTGRES_IMAGE`, `REDIS_IMAGE`; `mirror-images.sh --env-out` writes it).
  Compose pins by tag: make tags immutable in the registry.
- Helm (chart 0.31.0+): `templates/values-private-registry.yaml`
  (`global.imageRegistry`, `*.image.digest`, `imagePullSecrets`).
- Ansible: `templates/group_vars-private-registry.yml`
  (`openctem_registry_mirror`; the role verifies signatures at the mirror).
- Binaries: [binary-install.md](binary-install.md) with the release files from
  your raw proxy.
- Cluster enforcement: `templates/kyverno-verify-openctem-images.yaml`
  (identity-pinned keyless verification, tag to digest rewrite).

## Content and intelligence feeds

All outbound calls go through the SSRF-guarded client: an internal mirror on
a private address needs its range in `OPENCTEM_HTTPSEC_ALLOW_PRIVATE_CIDRS`,
and `HTTPS_PROXY` is not used.

| Feed | Offline path today | If absent |
|---|---|---|
| Vulnerability catalog (vulnfeed: CVE/NVD/OSV, emerging vulnerabilities) | signed bundles from `VULNFEED_BASE_URL`/`VULNFEED_MIRRORS` (a raw proxy) or files in `VULNFEED_BUNDLE_DIR`; verified against the pinned official root key id (`VULNFEED_ROOT_KEY_ID` overrides it); the source is on by default | catalog and inventory matching go stale (status turns stale after 3 days) |
| Public program feed (programfeed) | `PROGRAMFEED_URL`/`PROGRAMFEED_MIRRORS`, or a bundle in `PROGRAMFEED_DIR` | no public program catalog |
| Content catalog, content packs, scanner templates | admin import endpoints (content catalog needs `CONTENT_TRUST_ROOT_KEY_IDS`); template sources in internal git/S3 | |
| Sensor scanner content (nuclei, trivy, opengrep) | sensor-side local mirror or directory | sensor health shows stale content |
| Release feed / version check | admin import (`POST /api/v1/admin/version-check/import`) | newest versions not learned |
| CISA KEV, EPSS | none (fixed internet URLs) | no KEV flags, no EPSS scores |
| AI triage | none (provider URLs fixed) | AI triage unavailable |
| SMTP, Jira, chat, webhooks | internal targets work (private-range allowlist) | |
| Certificate transparency, RIPEstat (EASM) | none, internet-facing by nature | those EASM checks stop |

Gaps, planned as follow-ups: KEV and EPSS import (a file setting and an admin
upload, or carried in the signed vulnfeed bundle); an opt-in egress proxy for
the guarded client; an OpenAI-compatible base URL for an on-premises model;
serving the API reference page's script locally;
release-feed and content-root keys pinned in the release; platform alerts when
KEV, EPSS or vulnfeed go stale.

## Sensors

Sensor images and archives are released by openctemio/sensor and signed by
that repository's workflows: mirror them through the same paths with that
identity. A sensor inside the network pairs with the internal platform
address and verifies jobs against the job-signing key published by the
signer; it needs reach to its scan targets, not to the internet, once its
scanner content comes from a local mirror.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `x509: certificate signed by unknown authority` | the registry's CA is not trusted: add it to the host store (cosign, oras, containerd), Ansible `openctem_registry_ca_file` |
| `no signatures found` in the private registry | the image was copied without referrers (`docker pull/push`, `skopeo copy`, Harbor replication): copy again with `mirror-images.sh` (`oras cp -r`) |
| `no signatures found` through a Nexus proxy right after a release | a cached 404 for the `sha256-<digest>` tag: shorten the negative cache, invalidate the proxy cache, retry |
| `expected SAN ... refs/tags/vX, got ... refs/tags/vY` | the tag names another release's image: the source is wrong or tampered; do not promote |
| digest differs from the release list | the source re-tagged or the copy is not the release's: stop |
| `ImagePullBackOff`, `manifest unknown` | wrong `global.imageRegistry` path or arch missing (copy multi-arch indexes; never pull and push one arch) |
| `TOOMANYREQUESTS` from ghcr.io | let Nexus/Harbor cache; authenticate the proxy with a read-only token |
