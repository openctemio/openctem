### Behaviour change: unclassified assets get low-impact active checks behind platform guardrails

- An inventory asset that no scope entry covers and nobody excluded or
  rejected is no longer passive only: it now gets low-impact active checks
  (common ports at a low rate, HTTP GET of `/` and `/.well-known/*`, TLS and
  tech fingerprinting, nuclei info templates tagged tech or exposure). New
  scope setting `unclassified_scans`: `low_impact` (default), `off` (the old
  rule) or `full`; the Strict scan approval mode forces `off`. Changing it
  needs scope approve and step-up and is audited (RFC-054 §16).
- Platform guardrails keep an unclassified asset passive whatever the
  setting: addresses in CDN, shared-hosting or cloud networks, addresses with
  no network data, shared hosting, and names under none of the
  organization's domains (refusal code `guardrailed`). Its exact scope entry
  makes it scannable.
- A port scan of a name reaches only the web ports (80, 443, 8080, 8443)
  while an address the name resolves to is not in scope and may not be
  probed on its own, or nothing is known about its addresses (code
  `web_ports_only`); this also applies to names in scope.
- At claim, a job on unclassified targets that goes beyond the low-impact
  profile is clamped to it (or its unclassified targets are left out when it
  mixes them with in-scope ones). Port settings are now read from both
  `config` and `scanner_config`.
