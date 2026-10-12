### Changed: CI snippets and how-tos pin openctemio/ci v0.2.0

- The GitHub and GitLab snippets on the CI/CD integration page and the CI
  how-tos pin `openctemio/ci` v0.2.0 (diff-aware SAST on pull requests, the
  scanned image's digest, `.openctem.yml` gate settings, and OIDC reporting
  from Azure Pipelines, Bitbucket, CircleCI and Jenkins). The v0.9 upgrade
  guide no longer points at the `@v1` ref, which has no matching scanner
  images; pin a full release tag.
