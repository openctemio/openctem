# OpenCTEM @VERSION@: release archive

This archive installs one OpenCTEM component without containers. The full
guide (users, directories, systemd, upgrade, rollback, signature checks) is
`api/docs/deployment/binary-install.md` in the source repository and
"Install from binaries" on https://docs.openctem.io.

Before you unpack it, check the archive against the release's signed
`checksums-sha256.txt`:

    cosign verify-blob checksums-sha256.txt \
      --bundle checksums-sha256.txt.sigstore.json \
      --certificate-identity-regexp '^https://github.com/openctemio/openctem/.github/workflows/release.yml@refs/tags/v' \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com
    sha256sum --ignore-missing -c checksums-sha256.txt

Layout used by the bundled systemd units:

    /opt/openctem/<component>      -> the unpacked archive (a symlink)
    /etc/openctem/<component>.env  settings and secrets (root, 0640)
    /var/lib/openctem/...          state (created by systemd)

Contents: `bin/` programs, `systemd/` units and the sysusers file, `env/`
example settings, `VERSION` (version, commit, build time), `LICENSE`.
