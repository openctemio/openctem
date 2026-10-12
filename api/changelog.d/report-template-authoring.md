### Added: report template check, tag reference and three starter templates

- `POST /api/v1/pentest/report-templates/verify` lists every problem in a Word
  template without storing it, and `GET …/{id}/issues` re-checks a stored one:
  each issue names the part (body, header, footer) and the paragraph text and
  suggests the fix (the missing `{/x}`, the closest known tag for a typo, the
  loop an item field belongs in, `{@x}` for a Markdown field). Upload runs the
  same check and refuses a template with an error, saying how many problems
  there are.
- `GET /api/v1/pentest/report-templates/reference` answers every value a
  template can read (type, description in English or Vietnamese, example, tag
  to paste) and the sample data; it is generated from the same data model the
  renderer uses.
- Starter templates: `standard` (cover, table of contents, severity table,
  findings with evidence, remediation plan, appendix), `executive` (one page)
  and `technical` (one finding per page), with named Word styles and a header
  and footer; `GET …/starter?variant=`.
- New built-in labels for templates: `labels.contents`, `overview`,
  `appendix`, `methodology`, `team`, `name`, `role`, `client`, `contact`,
  `period`, `prepared_for`, `key_findings`, `no_key_findings`,
  `remediation_plan`, `details`, `reported`, `cvss`, `severity_ratings` and
  `<severity>_desc`.
