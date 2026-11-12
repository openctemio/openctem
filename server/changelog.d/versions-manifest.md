### Added: signed versions manifest for the documentation, the website and install scripts

- Every Release Feed run (after each release and every six hours) also publishes `openctem-versions.json` next to the release feed, signed by the same workflow identity: the newest stable platform release with its image digests, the oldest component releases it accepts, the newest sensor, SDK, CI runner and Helm chart, and the oldest platform each component release needs (`.github/release-feed/compat.json`). The documentation site and the website read it at build time, so a release needs no commit in either (`server/docs/architecture/versions-manifest.md`).
- A release is withdrawn from the manifest and the release feed by marking it a pre-release on GitHub and running the Release Feed workflow.
