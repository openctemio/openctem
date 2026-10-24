### Security: outbound connection guard hardened

- The outbound guard also refuses the IPv4-compatible IPv6 range (`::/96`).
- A refused or unresolvable destination no longer names the resolved address or the server's resolver in the error an organization sees (connection tests, rule-source status).
- Guarded HTTP clients refuse a redirect from https to http and stop after 5 redirects.
- Rule-source fetches have no ssh, `git://` or `file://` transport registered at all; only the guarded https transport exists.
- New architecture page: `docs/architecture/outbound-requests.md`.
