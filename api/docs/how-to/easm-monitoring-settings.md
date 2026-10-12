# Set attack-surface monitoring and run it now

Attack-surface monitoring runs two things on its own for your organization:

- **Certificate Transparency discovery** finds names under your seeds,
  verified domains and domain assets in public certificate logs. To do that,
  your domain names are sent to crt.sh and Cert Spotter.
- **DNS checks** look for dangling CNAME and NS records, lame delegations
  and weak email security (SPF, DMARC, MTA-STS, TLS-RPT). They use DNS only.

Both are on by default, about once a day.

## Where

**Attack surface** (`/attack-surface`) has a **Monitoring** card. It shows
when each part last ran, its switch and how often it runs.

| Action | Permission |
|---|---|
| See the card | `settings:read` |
| Turn a part off or on, change how often | `settings:write` |
| Run now | `attack_surface:scope:write` |

## Turn Certificate Transparency off

Turn it off when your domain names must not be sent to third parties. No new
names are then discovered from certificates. Names found before stay in the
inventory.

## How often

Choose **Default** (the platform cadence, usually 24 hours), or every 6, 12,
24 or 48 hours, or weekly. Six hours is the minimum, so third-party sources
and your DNS are not asked too often.

## Run now

**Run now** starts Certificate Transparency discovery and then the DNS
checks (each only if it is on). Results appear within minutes, in the review
queue, on Exposures and in this card. You can run again 15 minutes later.

Adding a seed with discovery on starts the same run for you automatically.

## API

```
GET  /api/v1/easm/settings
PUT  /api/v1/easm/settings   {"ct_enabled": true, "dns_checks_enabled": true, "ct_interval_hours": 0, "dns_interval_hours": 12}
POST /api/v1/easm/sweeps     -> 202, or 429 with Retry-After
```

Changes and runs are recorded in the audit log (`easm_settings.updated`,
`easm_sweep.requested`).
