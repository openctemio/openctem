# Harbor setup for OpenCTEM images (checklist)

Guide: `api/docs/deployment/air-gapped.md`. The API bodies in this folder are
for Harbor 2.x (`/api/v2.0`). Use them with an administrator account once and
keep that account out of CI.

## Projects

| Project | Purpose | Who writes | Who reads |
|---|---|---|---|
| `openctem-staging` | landing zone: images as they arrive (mirror job, replication) | `robot$openctem-mirror` | `robot$openctem-mirror`, the scanner |
| `openctem-trusted` | images that passed signature and vulnerability checks | `robot$openctem-mirror` (promotion only) | cluster and host pull robots |

- [ ] Both projects private (`"public": "false"`). Create `openctem-trusted`
      with `trusted-project.json` (`POST /api/v2.0/projects`).
- [ ] `openctem-staging`: scan on push on. No cluster pulls from it.
- [ ] `openctem-trusted`, Configuration:
  - [ ] Cosign content trust on (`enable_content_trust_cosign`): Harbor refuses
        to serve an image without a cosign signature. It checks that a
        signature EXISTS, not who made it: the identity check belongs in the
        promotion step (`mirror-images.sh`) and in the cluster (Kyverno, see
        `templates/kyverno-verify-openctem-images.yaml`).
  - [ ] Prevent vulnerable images from running: severity `critical` (or your
        policy), with a CVE allowlist only for reviewed exceptions.
  - [ ] Tag immutability rule: repositories `**`, tags `v*`. Docker Compose
        pins by tag; an immutable tag cannot be re-pointed.
  - [ ] Tag retention: keep the last 5 `v*` tags per repository (rollback
        window) and run garbage collection on a schedule.

## Robot accounts (least privilege, expiring)

- [ ] `robot$openctem-mirror` (the CI mirror job): project robot scoped to
      `openctem-staging` and `openctem-trusted`; permissions repository
      pull + push, artifact read, tag create. No delete, no project or member
      administration. Expiry 90 days; store it as a masked, protected CI variable;
      rotate before expiry.
- [ ] `robot$openctem-pull-<cluster>` (one per cluster or host group): only
      `openctem-trusted`, repository pull. Expiry 90 days. Kubernetes:
      `kubectl create secret docker-registry openctem-registry ...` and
      `imagePullSecrets` in the Helm values.
- [ ] The replication endpoint credential (`registry-endpoint-nexus.json`) is a
      read-only account of the Nexus proxy, nothing else.
- [ ] Audit log forwarded to your SIEM (Harbor: System Settings, Audit log
      forwarding): pushes, pulls, robot creation, policy changes.

## Getting images in

Supported and tested: `mirror-images.sh` (from the CI mirror job, or by hand).
It reads each image from the source (ghcr.io, a Nexus Docker proxy of it, or
an offline bundle), verifies the release signature, copies the image WITH its
signature and attestations (`oras cp -r`, stored through Harbor's OCI
referrers support, Harbor 2.8 or later), and verifies again in Harbor.

Harbor replication (`replication-rule-openctem.json`, from the Nexus proxy
endpoint or the `github-ghcr` endpoint) and a proxy cache project
(`proxy-cache-project.json`) also bring the images in, with the same digests.
Our signatures are stored on ghcr.io under the referrers tag schema (a tag
`sha256-<digest>` per image), which these features do not translate into
Harbor signatures: keep them as the feed of `openctem-staging` only, and
promote to `openctem-trusted` with `mirror-images.sh online <version>
<harbor>/openctem-trusted --source-prefix <Nexus proxy or ghcr.io>`, which
brings the signatures. Check in your Harbor version before relying on
anything else: `cosign tree <harbor>/openctem-trusted/openctem-api:<version>`
must list the signature.

## Egress exception (only when Harbor itself pulls from ghcr.io)

- [ ] Harbor's core and jobservice reach the internet only through the proxy
      in `templates/squid-egress-allowlist.conf` (Harbor: `HTTPS_PROXY` in
      `harbor.yml` `proxy:` section, components `core,jobservice,trivy`).
- [ ] Allowed names: `ghcr.io`, `pkg-containers.githubusercontent.com`; for
      Trivy's database: your mirror of it (preferred) or `ghcr.io` again.
- [ ] Replication filters name the exact repositories (no `openctemio/**`).
