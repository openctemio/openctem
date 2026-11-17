### Security: findings list rows mask secrets and e-mail addresses

- A findings row, a phone card and a group header no longer show an e-mail address, a URL credential or a
  secret in clear when a scanner, an importer or a person put one into a title, a location, a rule id or a
  group label. The address keeps its domain (`***@example.com`), a secret keeps at most its first and last
  4 characters (`AKIA••••••••MPLE`); tooltips and accessible names are masked the same way. Nothing is
  discarded, and "Show" stays on the finding page.
- Display only: the list response is unchanged, and no request, permission or data path is added.
- Docs: web/docs/findings-list.md ("Sensitive values in rows")
