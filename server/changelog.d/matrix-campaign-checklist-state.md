### Changed: layout matrix opens a pentest campaign's Checklist tab with recorded results

- The matrix seed (`web/e2e/ci/seed-matrix.sh`) adds the built-in OWASP Top 10 checklist to its pentest campaign and records passed, failed (with a note) and not applicable results on part of it, the rest untested.
- New route state `/pentest/campaigns/[id]@checklist` opens that tab (`?view=checklist`).
- Docs: none (test harness only; no product behaviour changes)
