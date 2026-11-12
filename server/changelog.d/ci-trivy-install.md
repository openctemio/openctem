### Changed: the image guard installs trivy from its release asset

- CI, the security scans and image publishing install the pinned trivy release straight from its GitHub release asset, checked against the published SHA-256 and retried on network errors, instead of the setup action's install script, whose downloads failed on the hosted runners and failed every merge group.
