# Security Policy

This policy covers everything in this repository (the API, the web console and
the all-in-one image) and the other `openctemio` repositories that link to it.

## Supported versions

Security fixes are released for the **latest minor release** (the newest
`vX.Y.*`). Upgrade to the latest patch of that minor release to receive them.
Older minor releases do not receive fixes.

## Reporting a vulnerability

**Do not open a public GitHub issue, pull request or discussion for a
vulnerability.**

Email **security@openctem.io** with:

- the affected component and version (or commit),
- a description of the vulnerability and its impact,
- step-by-step reproduction (a proof of concept, request/response samples or
  logs where possible),
- any suggested fix or mitigation,
- whether and how you would like to be credited.

Only test against an installation you own or are authorised to test, and use
test data. Stop and report as soon as you confirm the issue; do not access,
modify or keep data that is not yours.

## What to expect

| Step | Target |
|---|---|
| Acknowledgement of your report | within 3 business days |
| Triage (validity, severity, affected versions) | within 10 business days |
| Fix released | typically within 90 days, sooner for critical issues |

We keep you informed while we work on the fix, agree a disclosure date with you
(coordinated disclosure), publish a GitHub security advisory with the fixed
version, and credit you unless you prefer otherwise.

## Safe harbor

We will not pursue legal action against, or ask law enforcement to investigate,
anyone who researches and reports a vulnerability in good faith under this
policy: testing only systems they own or are authorised to test, avoiding
privacy violations, data destruction and service disruption, and giving us
reasonable time to fix the issue before any public disclosure.

## More

The full disclosure process is published at
<https://docs.openctem.io/security/vulnerability-disclosure/>.
