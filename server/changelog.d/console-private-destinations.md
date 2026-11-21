### Added: private network destinations in the platform console

- Console System > Private networks lists the private ranges (inside 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 or fc00::/7) the platform's outbound requests may reach, so a self-managed GitLab, Jira or mail relay on a private address can be opened without editing the server's environment and restarting it. Ranges set in `OPENCTEM_HTTPSEC_ALLOW_PRIVATE_CIDRS` are shown read only ("Set on the server"); the guard allows both lists.
- A change applies at once on the server that saved it and within 15 seconds on the others. At most 32 ranges; an IPv6 range must be /48 or narrower; loopback, link-local and cloud metadata addresses are never opened; nothing is opened while `SIGNUP_MODE=open`.
- "Test a destination" resolves a host name and reports, per address, whether it is reachable, which range opens it, the range that would open a blocked one, or why it is never reachable. It never connects to the host and is limited to 10 tests a minute per administrator.
- Docs: server/docs/deployment/docker.md#services-on-private-addresses-gitlab-jira-mail-relay

### Security: opening a private range is the platform owner's, with a fresh code and a reason

- New platform permission `platform.settings.network` (platform owner only, migration `20261118072557_platform_settings_network_permission`) for changing the list and running the destination test. A change needs a fresh step-up code and a reason, is a critical admin audit row with the previous and new lists, and every administrator is told. Organization sessions never reach these routes.
- Docs: server/docs/architecture/outbound-requests.md#private-network-destinations
