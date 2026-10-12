### Added: release images pass a size, non-root and OS-advisory gate before they are pushed

- `.github/scripts/image-guard.sh` runs on every image of a release (each
  architecture, before the push) and on the merge queue's image builds: a
  per-image size budget, a non-root user, no setuid/setgid file, and no
  fixable HIGH/CRITICAL advisory in OS packages (trivy). Advisories in
  application dependencies are listed as warnings.
