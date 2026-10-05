### Changed: CI guides pin the sensor image by digest and document the runner's security controls

- The GitLab and GitHub examples in the CI how-tos run a sensor release pinned by digest instead of the moving `latest-ci` tag, with the cosign command to verify a digest before pinning it.
- The GitLab guide's security notes cover protected refs, the run token's least privilege, budgets, secret handling, the minimum runner version, gate enforcement and audit.
