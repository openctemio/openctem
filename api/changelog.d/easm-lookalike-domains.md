### Added: passive lookalike-domain monitoring

- Attack surface › Lookalikes watches the organization's root domains (a
  permanent domain scope entry or a verified domain) for registered
  lookalikes: typos, keyboard neighbours, hyphens, bit flips, look-alike
  characters (incl. IDN) and other TLDs, tunable per domain (en, vi).
  RFC-083.
- Checks are passive only: DNS through the platform resolver and Certificate
  Transparency (crt.sh); no lookalike host is contacted. Registered names are
  re-checked daily, the rest weekly.
- A registered lookalike is a `lookalike_domain` exposure (medium with mail
  servers, or addresses and a certificate) announced like other EASM
  exposures, and triaged as ours or benign, not a threat, or taken down. One
  that stops resolving is resolved.
- `/api/v1/easm/lookalikes/watches` (scope permissions, audited).
- The organization can turn the crt.sh queries for lookalikes off on the
  monitoring card (`lookalike_ct_enabled`, on by default); DNS checks continue.
