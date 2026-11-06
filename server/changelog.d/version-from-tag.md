### Changed: The platform version comes from the tag, not from a committed value
- `docker-compose*.yml` no longer carry a default `OPENCTEM_VERSION`: `./setup.sh` writes it into `.env` from `--version vX.Y.Z`, else `api/deploy/VERSION` (present in a release tag's checkout), else the tag checked out. From a branch checkout, pass `--version`.
- `versions.yaml` no longer has `platform` or `chart` sections; the platform release the content catalog checks against is the running build's version.
- A release no longer opens a version-bump PR to `develop`: the follow-up after a train only merges `main` back (`-s ours`, no file change), and a hotfix has none.
