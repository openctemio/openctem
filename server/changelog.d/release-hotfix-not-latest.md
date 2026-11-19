### Fixed: a hotfix of an older release line no longer becomes the latest release

- Publishing a hotfix tag of an older line (for example v0.21.1 after v0.23.0) moved the `latest` image tag of every image, GitHub's "Latest" release and the release feed back to that hotfix. The publish now adds `latest`, marks the release as Latest and uploads the release feed only when the tag is the newest `vX.Y.Z` release tag; when the tags cannot be listed the job fails instead of guessing.
- Docs: none (release pipeline only; no change for installs)
