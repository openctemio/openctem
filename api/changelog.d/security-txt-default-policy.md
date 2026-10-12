### Changed: security.txt names the disclosure policy by default

- `/.well-known/security.txt` now carries `Policy: https://docs.openctem.io/security/vulnerability-disclosure/` while the contact is the default security@openctem.io. An operator who sets `SECURITY_CONTACT` gets no default `Policy` line and sets their own with `SECURITY_POLICY_URL`.
- `SECURITY.md` matches the published disclosure policy: GitHub private vulnerability reporting as a second channel, fix targets by severity, testing rules for services we operate, and the safe harbor.
