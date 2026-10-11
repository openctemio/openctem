### Added: release images carry a signed SLSA build provenance

- Every image of a release (`openctem-api`, `openctem-web`, `openctem`,
  `openctem-gateway`, `migrations`, `seed`, `admin-cli`) gets a SLSA build
  provenance attestation signed through Sigstore and stored in the registry
  next to the image, recording the workflow, commit and runner that built it.
  Verify with `gh attestation verify oci://ghcr.io/openctemio/<image>:<tag> --owner openctemio`.
