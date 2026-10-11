# Security Policy

This policy covers everything in this repository (the API, the web console and the all-in-one image) and is part of the OpenCTEM vulnerability disclosure policy, which also covers the other `openctemio` repositories and the services we operate.

## Reporting a vulnerability

**Do not open a public GitHub issue, pull request or discussion for a
vulnerability.** Report it privately through either channel:

- email **security@openctem.io**;
- GitHub private vulnerability reporting: **Security → Report a vulnerability**
  on this repository (it becomes a draft security advisory visible only to you
  and the maintainers).

Please include:

- the affected component (API, web console, all-in-one image) and version (or commit);
- a description of the issue and its impact, and the access an attacker needs
  first;
- step-by-step reproduction, a proof of concept or a failing test;
- any known mitigation or suggested fix;
- how you would like to be credited, if at all.

Test only against systems you own or are authorized to test, with test data.
On services we operate, use only your own accounts and organizations and never
point scans at third-party systems; stop and report as soon as you reach data
that is not yours. The full testing rules are in the disclosure policy below.

## What to expect

| Step | Target |
|---|---|
| Acknowledgement of your report | within 3 business days |
| Triage (confirmed or not, severity, next steps) | within 10 business days |
| Fix released, by severity (CVSS 3.1) | critical 7 days · high 30 days · medium 90 days · low best effort |

We follow coordinated disclosure: we keep you informed while we work on the
fix, agree a disclosure date with you, and publish a GitHub security advisory
with the fixed version, with a CVE identifier for a confirmed vulnerability in
released software.

## Acknowledgements and rewards

This is a vulnerability disclosure programme without monetary rewards. Unless
you prefer otherwise, we credit you on the
[security acknowledgements](https://docs.openctem.io/security/acknowledgements/)
page, in the security advisory and in the release notes of the fixed version.
**Bug bounty: coming soon** — a programme with rewards is planned; until it
starts, no report is eligible for a reward.

## Supported versions

Security fixes are released for the **latest minor release** (the newest `vX.Y.*`). Upgrade to the latest patch of that minor release to receive them. Older minor releases do not receive fixes.

## Safe harbor

We consider security research carried out in good faith under the disclosure
policy to be authorized: we will not initiate or support legal action against
you, or report you to law enforcement, for it, and we waive restrictions in our
terms of service that would otherwise prohibit it. Good faith means testing
only systems you own or are authorized to test, avoiding privacy violations,
data destruction and service disruption, and giving us reasonable time to fix
the issue before any public disclosure. If in doubt, ask security@openctem.io
first.

## More information

The full vulnerability disclosure policy (scope, testing rules, safe harbor):
<https://docs.openctem.io/security/vulnerability-disclosure/>.
