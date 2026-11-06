# Sign-up activity: feed and burst alerts

Operators of a deployment with open sign-up need to see who is signing up and
to hear about a burst (a bot farm, a scripted abuse wave) without collecting
more personal data than that needs. The platform console has a sign-up feed
(Customers > Sign-ups) and raises an alert when sign-ups from one network or
one email domain pile up.

## What is recorded

One row in `signup_events` per:

| Kind | Sources |
|---|---|
| `account_created` | `password` (public registration), `invitation` (registration with an invitation), `oauth` (first social sign-in), `sso` (just-in-time account of an organization's OIDC or SAML sign-on) |
| `organization_created` | `self_service` (a signed-in person, `POST /auth/create-first-team` or `POST /tenants`), `console` (a platform administrator), `access_request` (an approved access request), `control_plane` (the hosted service's internal API) |
| `access_requested` | `public` (the request-access form; only stored requests, not ones the per-address, per-domain or disposable-address rules dropped) |

Each row keeps:

- the **registrable domain** of the email address (`mail.example.co.uk`
  gives `example.co.uk`), never the address or its local part;
- the **client network prefix**: /24 for IPv4, /48 for IPv6, from
  `pkg/httpsec` (the TCP peer, or the forwarded address only behind a trusted
  proxy). A database check refuses anything narrower. Events of the operator
  paths (`console`, `access_request`, `control_plane`) keep no prefix: the
  address would be the operator's own;
- the organization and account ids, for the console's links. They are set to
  NULL when the organization or the account is deleted, and account erasure
  clears the account id. The feed API does not return the account id.

No name, user agent or full address is stored. Rows are deleted after 90 days
(`signup-event-retention` controller, hourly, one replica).

Recording is best effort and detective: a failed insert is logged and never
fails or delays the sign-up (each event has a 3-second budget). The preventive
controls (sign-up policy and its ceiling, CAPTCHA, email verification,
disposable-domain block, rate limits) never read it.

## Burst alerts

Self-service events are counted in Redis per kind, per network prefix and per
email domain, in fixed windows (`signupburst:*` keys, which expire after two
windows). The first time a count reaches its threshold in a window the API:

1. increments `openctem_signup_burst_alerts_total{dimension,kind}` (labels
   are the dimension and the kind only; the monitoring stack's `SignupBurst`
   rule pages from it, see `docs/operations/monitoring.md#signupburst`);
2. writes a WARN log line with `alert=signup_burst`;
3. writes a **high** row `platform.signup_burst` to the console admin audit
   log naming the prefix or the domain, the count and the threshold;
4. emails the active platform administrators through the system email sender
   (same path as the Health page's system watcher), naming the prefix or domain and
   the count, never a person.

Defaults: 10 events of a kind from one prefix, or 20 from one email domain,
within 60 minutes. A super admin changes them in the console (a reason and a
fresh authenticator code; optimistic version; audited **critical**; the
administrators are emailed). 0 turns a dimension off. Ignored domains (up to
50; large consumer mail providers, the operator's own domain) skip the
per-domain count; the per-prefix count still covers them. Without Redis the
events are still recorded and the alerts are off; an unreadable setting falls
back to the defaults so the alerts stay on.

## API

| Route | Who |
|---|---|
| `GET /api/v1/admin/signup-events?kind=&page=&per_page=` | any console role |
| `GET /api/v1/admin/signup-events/daily?days=` (1-90) | any console role |
| `GET /api/v1/admin/settings/signup-alerts` | any console role |
| `PUT /api/v1/admin/settings/signup-alerts` | super admin, reason, fresh authenticator code |

No tenant route reads or resets the events or the counters.

## Threat model

- **Privacy:** the feed is aggregate data an operator needs to spot abuse.
  Domain and prefix are the coarsest values that still separate a bot farm
  from a company rollout. Metrics and alerts carry no domain or prefix; the
  admin audit row and the administrators' email do, and both stay inside the
  platform's administrator realm.
- **Alert suppression:** an attacker who spreads sign-ups across many /24s
  and domains stays under the thresholds; the alert is a signal, the rate
  limits and the sign-up policy are the controls. Thresholds can only be
  raised by a super admin with step-up, and the change is audited and mailed
  to every administrator.
- **Alert flooding:** one alert per dimension, value, kind and window (Redis
  `SET NX`), so a burst sends one email, not one per sign-up.
- **Isolation:** `signup_events` is a platform table read only by the console;
  the tenant id is a link for the operator, never a filter a tenant controls.

## Code

`pkg/domain/signupevent` (event, domain and prefix reduction, thresholds),
`internal/app/signupevent` (recorder, burst counting, console reads),
`internal/infra/postgres/signup_event_repository.go`,
`internal/infra/http/handler/admin_signup_event_handler.go`,
`internal/infra/controller/signup_event_retention.go`,
`cmd/server/signup_events_wiring.go`, migration `signup_events`; console page
`web/src/app/(admin-console)/admin/signups`.
