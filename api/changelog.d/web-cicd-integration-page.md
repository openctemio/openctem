### Changed: CI/CD integration has its own page; the Sensors page opens on the sensors

- New page **Discovery > CI/CD** (`/ci-cd`, `scans:ci:read`, `scans` module): CI pipelines, their runs and repository coverage, plus a **Trust and gate** tab (trust configurations, gate policy, break-glass) and links to the GitHub Actions and GitLab CI guides.
- The Sensors page opens on the sensors in your networks (daemon mode) and links to CI/CD with the number of active pipelines; the Runner and All modes stay available.
- `/ci-runners`, `/ci-runners/{run}` and the old runner-sensor list `/runners` redirect (308) to CI/CD. The settings entry is renamed **CI/CD integration**.
