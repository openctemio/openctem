### Security: requiring SSO needs a verified domain, and a lapsed domain alerts without lifting enforcement

- Turning SSO enforcement on for an organization (platform console) is refused unless the organization has at least one domain verified for SSO by DNS. The check fails closed. An organization that already enforces SSO is not affected, and turning enforcement off is never blocked.
- When a domain verified for SSO fails its periodic DNS re-check, the owners and administrators get an in-app alert (High). SSO enforcement deliberately stays on: lifting it would reopen password sign-in to whoever removed the DNS record.
