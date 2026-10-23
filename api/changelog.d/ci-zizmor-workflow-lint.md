### Changed: workflow lint runs zizmor

- The Workflow Lint job now runs zizmor (pinned, checksum-verified) next to actionlint. The first run's findings are fixed: checkouts that push nothing no longer persist credentials, `github.base_ref`, `github.ref_name` and matrix values reach scripts through the environment instead of being expanded into the script text, and Dependabot waits seven days after a release before proposing it (security updates are not delayed).
- Findings that cannot be fixed are listed with a reason in `.github/zizmor.yml`.
- No operator action.
