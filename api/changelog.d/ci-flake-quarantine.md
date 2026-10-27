### Added: flaky-test quarantine with an owner and a fix date

- `.github/quarantine.yml` lists flaky tests that API CI (`go test -skip`) and Web E2E (`--grep-invert`) skip until their `fix_by` date, at most 14 days after they were added; then they run again. Each entry names its tracking issue and owner. Security tests are refused, and the list is a security-sensitive path (adding an entry needs `security-ack`). Checked by `.github/scripts/quarantine.py check` in Workflow Lint.
