### Added: sign-up feed and burst alerts in the platform console

- Console > Requests > Sign-ups lists accounts created, organizations created
  and access requests submitted, with daily counts, kept 90 days. Each event
  keeps only the registrable email domain and the client network prefix (/24
  or /48); never the address, a name or a user agent (migration
  `signup_events`).
- When sign-ups of one kind from one network or one email domain reach a
  threshold within a window (default 10 per network, 20 per domain, an hour),
  the API raises one alert: the metric
  `openctem_signup_burst_alerts_total{dimension,kind}` (new monitoring rule
  `SignupBurst`), a WARN log line `alert=signup_burst`, a high admin audit row
  `platform.signup_burst` and an email to the platform administrators.
- A super admin changes the thresholds and the ignored domains with a reason
  and a fresh authenticator code (`PUT /api/v1/admin/settings/signup-alerts`,
  audited critical). Any console role reads the feed
  (`GET /api/v1/admin/signup-events`, `/daily`).
- **Upgrade note:** burst alerts need Redis; without it events are still
  recorded.
