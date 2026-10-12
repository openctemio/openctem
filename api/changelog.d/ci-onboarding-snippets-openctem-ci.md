### Fixed: the CI/CD page's GitHub and GitLab snippets run the CI scanner

- The pipeline snippet of a GitHub or GitLab trust configuration ran the
  sensor's former CI image (`sensor:latest-ci`) with flags the sensor no
  longer has (`-auto-ci`), so a pipeline copied from the console failed. It
  now uses the openctemio/ci reusable workflow (GitHub) or template include
  (GitLab), pinned to a release: one job per capability (SAST, SCA, secrets,
  IaC) with the job's OIDC token and one gate job. A trust configuration with
  its own audience passes it (`oidc-audience`, or each GitLab job's
  `id_tokens`).
