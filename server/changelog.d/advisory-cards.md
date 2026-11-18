### Added: advisory cards and exploitation evidence in emerging-threat alerts

- The vulnerability bundle importer reads the optional `cards` stream of the signed intel side manifest: reviewed, product-level advisory cards that can exist before a CVE record or CPE, with affected and fixed versions per branch, required configuration, exploitation status, proof-of-concept link metadata, workarounds, detection ideas and a cited source for every fact. Every revision is kept. Migration `advisory_cards`.
- An organization gets one emerging-threat alert per card, with the card's vulnerabilities grouped inside it; their own open alerts are resolved with the reason `grouped_into_card` (nothing is deleted). A withdrawn card resolves its alerts and its vulnerabilities are planned on their own again.
- The Emerging Threat Score counts exploitation stated by a reviewed card: vendor-confirmed or exploited in the wild 40, weaponised 30, public proof of concept 20. The breakdown names the evidence (`exploitation_basis`).
- A critical vulnerability with a public exploit on a possibly affected, internet-facing asset of critical business criticality sends one immediate "check needed" alert.
- `GET /api/v1/emerging-threats/{id}` adds `card`, `exploitation` and `exploitation_sources`.
- Docs: server/docs/rfcs/RFC-117-emerging-threat-alerts.md (§3.2, §3.5), server/docs/architecture/emerging-threat-alerts.md
