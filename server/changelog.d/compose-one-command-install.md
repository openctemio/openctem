### Added: one-command Compose install (`server/deploy/install.sh`)

- `install.sh` takes a Linux host from nothing to a running, healthy stack: it checks Docker Engine and the
  Compose plugin (and offers Ubuntu's packages when they are missing), the host's memory, disk, ports,
  network, DNS and clock, asks at most five questions with defaults (host name, Let's Encrypt or the
  built-in CA, the first and break-glass administrators, the bundled sensor), writes `.env` through
  `setup.sh`, verifies every release image's keyless signature in a cosign container pinned by digest and
  checks the pulled digests against it, runs the configuration check, starts the stack, waits for it to be
  healthy, creates the first administrators with `bootstrap-admin` and prints the URLs and the first
  sign-in.
- Unattended: every answer is an option or an `OPENCTEM_INSTALL_*` variable, `--yes` never asks, and a
  missing required answer is an error. Without a terminal the one-time credentials go only to a new
  `--credentials-file` (mode 0600).
- Idempotent: an existing `.env` is reused and never overwritten; the compose file set is recorded in
  `.env` (`COMPOSE_FILE`), and a change to it is backed up first and printed. It stops with the exact
  `.env` line to add when a stack of the same project name runs elsewhere or with an overlay the file set
  lacks.
- `setup.sh --set NAME=VALUE` writes any other setting into the new `.env`; a typed secret is checked for
  characters that would break a connection URL or Compose and for its length.
- Releases ship the Compose files as `openctem-compose-vX.Y.Z.tar.gz`, covered by the signed
  `checksums-sha256.txt`, so the install needs no git checkout: download, verify, then run.
- Docs: server/docs/deployment/docker.md#one-command-install
