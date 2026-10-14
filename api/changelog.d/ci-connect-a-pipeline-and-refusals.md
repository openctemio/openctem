### Added: connect a pipeline in four steps, and see why a pipeline was refused

- `GET /api/v1/ci/trust-refusals` (`scans:ci:write`) lists the organization's latest refused CI token exchanges from the audit log, newest first, at most 50. Each entry carries the repository, provider, ref, event, time and the rule codes that refused it. Only verified tokens are recorded.
- The CI/CD page has **Connect a pipeline**, on the empty Pipelines view and in the Trust tab:
  1. choose the CI system;
  2. name the organization (GitHub App installations are offered);
  3. the trust configuration is created and the pipeline snippet shown;
  4. wait for the first run.

  While waiting, it checks for runs and refusals every 10 seconds. A refused pipeline shows the rule that refused it and how to fix it.
- The Trust tab lists **Recent refused pipelines** with translated reasons. People without CI write permission are told to ask an administrator.
