### Fixed: dashboard figures count your organization, and every tile opens the list it counts

- The "Threat intel" widget showed the size of the global KEV catalog (about 1,700 entries, the same
  for every organization). It now shows your open findings in the KEV catalog, how many are past the
  KEV due date, and your open findings with EPSS of at least 50 %; the KEV figure opens that list.
- The CTEM view's threat intel card showed catalog-wide "Ransomware KEV" and "KEV new · 30d" counts.
  `GET /api/v1/threat-intel/stats` now also returns `kev.tenant_ransomware_open_count` and
  `kev.tenant_new_kev_matches_30d` (your open KEV findings with known ransomware use, and those whose
  CVE entered the catalog in the last 30 days), counted in your data scope with the pentest visibility
  rule; the card shows only tenant figures. The catalog fields keep their names and meaning.
- "Mine · open" opened every state; it now opens the open list it counts. "Open findings" opens the
  open list, and each row of "Open findings by severity" opens that severity.
- A figure that is not measured (no open finding has an SLA, a failed read) is neutral grey on the
  CTEM loop, never green or amber. "Average asset risk" shows "—" instead of 0 when there is no figure.
- A tenant with no open finding sees "No open findings" with a link to scans instead of a big "0 P0".
- "New findings per month" is drawn as columns (a flow) with the legend in severity order.
- One dashboard card that fails to render shows its own error with Retry; the rest of the page renders.
- Dashboard card titles, stage names and empty states are translated (English and Vietnamese).
