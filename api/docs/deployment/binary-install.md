# Install from the release archives (no containers)

Every release attaches archives that run OpenCTEM as ordinary programs under
systemd, for hosts where containers are not an option. They hold the same
programs as the images, built from the same commit with the same pinned
tools. Container images remain the main supported install
([docker.md](docker.md), [kubernetes.md](kubernetes.md)); this page is the
non-container one.

## What a release ships

| Archive | Platforms | Contents |
|---|---|---|
| `openctem-server-<v>-linux-<arch>.tar.gz` | linux amd64, arm64 | `openctem-server` (API) and its operator commands as links (`bootstrap-admin`, `refingerprint`, `repomerge`, `ci-trust-scope-plan`), `openctem-signer` (job signer), `migrate` (golang-migrate) and `openctem-migrate` (its wrapper), `migrations/`, `configs/`, `api/openapi/swagger.yaml`, systemd units for the server, the signer and migrations, env examples |
| `openctem-gateway-<v>-linux-<arch>.tar.gz` | linux amd64, arm64 | `caddy` with the layer4 module (the gateway image's build), the gateway configuration and entrypoint, systemd unit, env example |
| `openctem-web-<v>-linux-<arch>.tar.gz` | linux amd64, arm64 (glibc) | the web console as a Next.js standalone bundle, systemd unit, env example, `NODE_VERSION` |
| `openctem-console-<v>-linux-<arch>.tar.gz` | linux amd64, arm64 (glibc) | the platform console, same layout |
| `bootstrap-admin-<v>-<os>-<arch>.tar.gz` (`.zip` on Windows) | linux, macOS amd64/arm64, Windows amd64 | the first-administrator CLI as a standalone binary (the API image already contains it as `/app/bootstrap-admin`) |
| `openctem-image-kit-<v>.tar.gz` | any | private registry and air-gap kit ([air-gapped.md](air-gapped.md)) |
| `*.spdx.json` | | an SPDX SBOM per archive |
| `checksums-sha256.txt` + `.sigstore.json` | | sha256 of every archive and SBOM, signed keyless by the Release workflow |

The Go programs are static (CGO off), built with `-trimpath` and the commit
time as build time: the same tag gives byte-identical archives. The web and
console bundles need **Node.js** at the major version in their `NODE_VERSION`
file (the one in `web/.nvmrc`), installed from your distribution or
nodejs.org; they hold native modules (sharp) for glibc, so they run on glibc
distributions (Debian, Ubuntu, RHEL and derivatives), not Alpine/musl. Node.js
is not bundled: it gets security releases between ours, and your package
manager should apply them.

Not shipped as archives: PostgreSQL (16, 17 or 18; 17 recommended) and Redis 7
(use your distribution's or a managed service), the scanning sensor (released by openctemio/sensor with its
own signed archives), the all-in-one image (containers only).

## 1. Verify the download

```bash
V=v0.13.0
base=https://github.com/openctemio/openctem/releases/download/$V
for f in checksums-sha256.txt checksums-sha256.txt.sigstore.json \
         openctem-server-$V-linux-amd64.tar.gz openctem-gateway-$V-linux-amd64.tar.gz \
         openctem-web-$V-linux-amd64.tar.gz openctem-console-$V-linux-amd64.tar.gz; do
  curl -fsSLO "$base/$f"
done
cosign verify-blob checksums-sha256.txt --bundle checksums-sha256.txt.sigstore.json \
  --certificate-identity "https://github.com/openctemio/openctem/.github/workflows/release.yml@refs/tags/$V" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum --ignore-missing -c checksums-sha256.txt
# Optional: the SLSA build provenance of an archive
gh attestation verify openctem-server-$V-linux-amd64.tar.gz --owner openctemio
```

Stop if any check fails. On a host without internet access, verify on the
machine that downloaded the files, or copy a Sigstore `trusted_root.json`
there and add `--offline --trusted-root trusted_root.json`
([air-gapped.md](air-gapped.md#verifying-signatures-without-internet-access)).

## 2. Users and directories

```bash
sudo install -d -m 0755 /opt/openctem
sudo install -d -m 0750 -o root -g root /etc/openctem
for c in server gateway web console; do
  sudo tar -C /opt/openctem -xzf openctem-$c-$V-linux-amd64.tar.gz
  sudo ln -sfn openctem-$c-$V-linux-amd64 /opt/openctem/$c
done
sudo install -m 0644 /opt/openctem/server/systemd/openctem.sysusers /etc/sysusers.d/openctem.conf
sudo systemd-sysusers
sudo install -m 0644 /opt/openctem/server/systemd/*.service /opt/openctem/gateway/systemd/*.service \
  /opt/openctem/web/systemd/*.service /opt/openctem/console/systemd/*.service /etc/systemd/system/
```

| Path | Owner, mode | Holds |
|---|---|---|
| `/opt/openctem/<component>` | root, read-only to services | a symlink to the unpacked archive: upgrade and rollback switch the link |
| `/etc/openctem/<component>.env` | root:<service group>, 0640 | settings and secrets |
| `/var/lib/openctem/server` | openctem, 0750 (systemd `StateDirectory`) | attachments, sensor CA |
| `/var/lib/openctem-signer/{keys,state}` | openctem-signer, 0700 | the job-signing key and its state: the API user cannot read them |
| `/run/openctem-signer` | openctem-signer:openctem, 0750 | the signer's socket, reachable by the API only |
| `/var/lib/openctem/gateway` | openctem-gateway, 0700 | Caddy's certificates and internal CA |
| `/var/cache/openctem/{web,console}` | openctem-web, 0750 | the Next.js cache |

Users (`openctem.sysusers`): `openctem` (API), `openctem-signer` (signer,
primary group `openctem` for the socket only), `openctem-web` (web and
console), `openctem-gateway`. None has a shell or a home directory.

## 3. Configure

```bash
cd /opt/openctem
sudo install -m 0640 -g openctem server/env/server.env.example /etc/openctem/server.env
sudo install -m 0640 -g openctem server/env/signer.env.example /etc/openctem/signer.env
sudo install -m 0640 -g openctem server/env/migrate.env.example /etc/openctem/migrate.env
sudo install -m 0640 -g openctem-web web/env/web.env.example /etc/openctem/web.env
sudo install -m 0640 -g openctem-web console/env/console.env.example /etc/openctem/console.env
sudo install -m 0640 -g openctem-gateway gateway/env/gateway.env.example /etc/openctem/gateway.env
sudoedit /etc/openctem/server.env   # database, Redis, APP_URL, secrets (openssl rand -hex 32)
# Validate without connecting to anything. systemd-run reads the env file
# itself, so no secret appears on a command line:
sudo systemd-run --pipe --wait --quiet --uid=openctem --gid=openctem \
  -p EnvironmentFile=/etc/openctem/server.env -p WorkingDirectory=/opt/openctem/server \
  /opt/openctem/server/bin/openctem-server -check-config
```

The database roles follow [database-roles.md](database-roles.md): the API
connects as `DB_USER` (DML only); migrations run as the schema owner from
`migrate.env`, whose URL carries no password (it is read from `PGPASSWORD`, so
it never appears in a process list). Every setting:
[environment variables](../configuration/environment-variables.md).

## 4. First start

```bash
sudo systemctl daemon-reload
sudo systemctl start openctem-migrate          # schema (one shot)
sudo systemctl enable --now openctem-signer openctem-server openctem-web openctem-console openctem-gateway
# Create the first administrator (flags: bootstrap-admin -help):
sudo systemd-run --pipe --wait --quiet --uid=openctem --gid=openctem \
  -p EnvironmentFile=/etc/openctem/server.env \
  /opt/openctem/server/bin/bootstrap-admin -help
curl -fsS http://127.0.0.1:8080/health
journalctl -u openctem-server -f
```

## Hardening in the units

Every unit runs as its own user with `NoNewPrivileges`, an empty capability
set (the gateway keeps only `CAP_NET_BIND_SERVICE` for ports 80/443),
`ProtectSystem=strict` (only its state, cache or runtime directory is
writable), `ProtectHome`, `PrivateTmp`, `PrivateDevices`, kernel and cgroup
protection, `RestrictAddressFamilies`, `RestrictNamespaces`,
`SystemCallFilter=@system-service` and `UMask=0027`. The Go services add
`MemoryDenyWriteExecute`; the Node.js ones cannot (the JavaScript engine
compiles at run time). The signer has no network at all (`PrivateNetwork`,
`IPAddressDeny=any`, `AF_UNIX` only). `systemd-analyze security` rates every
unit 2.0 or lower ("OK"); the release pipeline fails above 2.5.

## Upgrade

Read the release's upgrade notes, back up the database and
`/var/lib/openctem`, then:

```bash
V=v0.14.0   # verify the new archives first (step 1)
for c in server gateway web console; do sudo tar -C /opt/openctem -xzf openctem-$c-$V-linux-amd64.tar.gz; done
sudo systemctl stop openctem-server
for c in server gateway web console; do sudo ln -sfn openctem-$c-$V-linux-amd64 /opt/openctem/$c; done
sudo systemctl start openctem-migrate         # applies the new migrations
sudo systemctl restart openctem-signer openctem-gateway openctem-web openctem-console
sudo systemctl start openctem-server          # refuses to start on an older schema
```

Compare the unit files and env examples of the new archive with the installed
ones (`diff /opt/openctem/server/systemd/openctem-server.service /etc/systemd/system/`)
and run `systemctl daemon-reload` after copying changes.

## Rollback

Switch the symlinks back to the previous archive and restart. A release that
applied migrations needs the database restored from the backup taken before
the upgrade (or its down migrations, if the release notes say they are
safe): the previous server refuses a newer schema only when files are
missing, so never run an older server on a schema it does not know.

## Unsupported

- The all-in-one layout (every service in one process tree): containers only.
- musl-based distributions for the web and console bundles.
- Running the API and the signer as the same user, or the signer with network access.
- Windows and macOS for anything but `bootstrap-admin`.
