### Added: emerging-threat alerts

- One alert per organization and vulnerability when a vulnerability becomes urgent (new CVE with affected products, CISA KEV addition, EPSS crossing) and affects the organization's assets: confirmed (an open finding) or possibly affected (the product runs on the asset, its version is unknown). A transparent Emerging Threat Score decides between an immediate message (needs exploitation evidence), the daily digest (08:00 organization time) and the list only (RFC-117, migrations `003101`, `003102`).
- At most five immediate messages per organization per hour (the rest in one summary), one message per alert and level, optional quiet hours (an alert scoring 90 or more still pages). The first run in each organization computes a baseline and sends only one baseline digest, no immediate storm.
- Delivered through the existing channels (new event types `emerging_threat`, `emerging_threat_digest`, added to every channel that receives new findings or priority escalations), in-app to administrators, and by e-mail to members whose e-mail digest preference is daily or weekly (the preference had no effect until now). External messages carry counts and a link; asset names only when the organization turns them on (at most five).
- API: `GET /api/v1/emerging-threats`, `GET /api/v1/emerging-threats/{id}`, `POST /api/v1/emerging-threats/{id}/state` (triage: acknowledged, remediating, not affected with a reason, reopen), `GET/PUT /api/v1/organization/settings/emerging-threats`. Existing permissions only; every read is narrowed to the caller's data scope.

### Changed: matched findings are announced, KEV escalations once

- Findings created by inventory vulnerability matching were stored without any notification; they are now announced by their emerging-threat alert.
- When an alert covers a CVE that entered KEV, the per-finding priority-escalation message is no longer sent (one alert instead of one message per finding).
