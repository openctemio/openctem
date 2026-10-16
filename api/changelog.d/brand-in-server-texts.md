### Changed: emails, reports, notifications and API pages name the configured brand

- Every text the API writes for people now names `BRAND_NAME` instead of a
  fixed "OpenCTEM": report footers and scheduled report subjects, test
  notifications and their footers, Jira and GitHub ticket comments, CI pull
  request comments, MCP texts, the OAuth error page, the API reference page,
  generated sensor configuration and the admin two-factor issuer.
- Emails carry `BRAND_EMAIL_FOOTER` and, for a brand other than OpenCTEM,
  the "Powered by OpenCTEM" credit unless `BRAND_POWERED_BY=false`.
- Documentation links of sensor configuration checks and the welcome email
  point at `BRAND_DOCS_URL`, keeping their path.
- Technical identifiers do not change (headers, image names, the CI check
  name, protocol and policy identifiers). With no `BRAND_*` set, every text
  is as before.
