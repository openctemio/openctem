### Security: the allow-every-private-range switch is development only

- `OPENCTEM_HTTPSEC_ALLOW_PRIVATE=1` opened every RFC 1918 / ULA range to
  every tenant-supplied URL (webhooks, SMTP, Jira, SCM, CI issuers, LLM, S3),
  which let any tenant admin reach the platform's own network. It is now
  honored only with `APP_ENV=development`; in any other environment the API
  refuses to start, and a binary that does not check still keeps the ranges
  blocked. A value other than empty, `0` or `1` is refused too.
- New `OPENCTEM_HTTPSEC_ALLOW_PRIVATE_CIDRS`: comma-separated private ranges
  the API may reach (each inside 10/8, 172.16/12, 192.168/16 or fc00::/7),
  logged at start-up. Loopback, link-local/metadata and CGNAT stay blocked.
- **Upgrade note:** an on-prem install that set
  `OPENCTEM_HTTPSEC_ALLOW_PRIVATE=1` replaces it with the subnet(s) it needs,
  for example `OPENCTEM_HTTPSEC_ALLOW_PRIVATE_CIDRS=10.20.0.0/16`.
