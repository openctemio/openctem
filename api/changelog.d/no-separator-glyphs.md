### Changed: threat alert reasons are separated by commas

- The "why now" line of an emerging-threat notification (Slack, email, webhook text) now reads "in the CISA KEV catalog, EPSS 0.97, severity critical" instead of joining the facts with a middle dot.
- The web console gains a CI check that refuses new separator glyphs in UI text, a dot-free `MetaLine`, a `formatList` helper and a `LabelSegments` primitive. No page is migrated yet.
