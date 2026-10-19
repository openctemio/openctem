### Security: refuse the published development sensor CA

- The API now refuses to load a sensor CA whose SHA-256 fingerprint is
  `F6:BD:9D:E7:0E:E4:06:1B:2B:7C:57:E7:F5:24:FA:29:D7:9B:73:23:06:E5:81:BA:44:05:72:E1:D4:3D:83:CD`.
  That development CA's private key was committed to the repository for a few
  days in October 2026 and is in the v0.9.6 and v0.9.7 source archives, so
  anyone could impersonate the platform to sensors that pin it. If you started
  the API from one of those archives with transport v3 on, startup now stops
  with an error: delete the CA directory (`SENSOR_MTLS_CA_DIR`, default
  `data/sensor-ca`) or point `SENSOR_MTLS_CA_CERT_FILE` and
  `SENSOR_MTLS_CA_KEY_FILE` at your own CA, then start the API again. A new CA
  is generated and sensors pin it on their next enrollment.
- Repository checks: secret scanning blocks pull requests, its allowlist no
  longer exempts every Markdown file and script, the customer and commit-email
  denylist checks fail instead of skipping when their secret is missing on the
  main repository, and the live network range check also covers test files.
  Test fixtures and docs use reserved example names and documentation address
  ranges.
