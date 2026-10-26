# Web content pipeline: posture, labels, verification and change alerts

Builds on the web surface store ([web-surface.md](web-surface.md), RFC-056).
No new asset type and no URL asset: origins stay `http_service` assets and
endpoints stay sub-inventory rows. This slice fills the store with a few
derived facts and gives them consequences.

## Rules that hold everywhere

- **No values are stored.** Not parameter values, query values, cookie
  values, header values, nor secret plaintext. The only header-derived data
  is the posture below, reduced to typed flags and enums.
- **A catalog match is a label, never a finding.** A finding comes only from
  a signed template hit (see Verification).
- **Excluded paths are stored for visibility and never fetched, verified or
  alerted.**
- Every read and write is tenant-scoped; every list is narrowed to the
  caller's data scope through the origin asset.

## Header posture (`http_posture`)

An attribute of the origin asset (type `object` on `http_service`). A
producer may send it; a report without it changes nothing. At ingest the
platform keeps only these keys, each coerced to its type, and drops every
other key (and the key on any other asset type):

| Key | Type |
|---|---|
| `hsts`, `hsts_include_subdomains`, `hsts_preload`, `csp`, `csp_unsafe_inline`, `csp_unsafe_eval`, `nosniff`, `permissions_policy`, `cors_credentials` | boolean |
| `hsts_max_age` | integer seconds, 0 to ten years |
| `frame_options` | `deny`, `sameorigin`, `allow_from`, `other` |
| `referrer_policy` | the standard policy tokens, or `other` |
| `cors_origin` | `none`, `wildcard`, `specific`, `reflected` |
| `cookies` | at most 20 entries `{name, secure, httponly, samesite}`; `name` matches `[A-Za-z0-9_.-]{1,64}`; `samesite` is `strict`, `lax` or `none` |

Posture is never a finding by itself.

## Labels at ingest

The platform sets `ext:backup|config|archive|dbdump|source|log` from the
path template's extension, and `auth:login` when the endpoint has a
password field (type hint `password`, or a form parameter named like one).
Labels are merged on later sightings; a person's labels are kept.

## Verification planner

`internal/app/webverify`, run every 15 minutes by the `web-verify`
controller (one replica at a time).

1. Candidates: endpoints that are active, in scope, not under an exclusion,
   method GET, answered 2xx, whose catalog entry has a `verify` block (the
   20 most critical entries map to template ids of the signed pack), and
   that were never verified for their current response signature
   (`web_endpoint_verifications`).
2. The tenant's path exclusions are loaded again at planning time. If they
   cannot be read, nothing is planned.
3. Budget: 100 endpoints per tenant per rolling day, 25 per pass.
4. URLs are grouped by template set and dispatched by
   `scan.Service.StartWebVerification` as the `web_verify` system policy at
   tier T1: scope entries, ownership, exclusions and zones apply as for
   coverage runs, and the web job guard attaches the path limits. The scan
   config carries `template_ids`.
5. The run files findings only through the normal ingest of the template
   hits. The planner itself writes no finding and no exposure.

A depth never raises the tier: passive verifies nothing, standard and deep
are T1 (deep doubles the budget). `dast.web` (T2) is never planned here.

## Change kinds and alerts

The typed change feed (RFC-080) reads `web_endpoint_events` as:

| Kind | Trigger |
|---|---|
| `web_sensitive_new` | an in-scope active endpoint of a catalog entry of severity high or critical (or a `panel:*` label) appeared or returned |
| `web_auth_lost` | `auth_changed` from required or a login redirect to none, on a catalog or API/GraphQL endpoint |
| `web_param_added_sensitive` | a parameter was added to a catalog endpoint, or a credential-class parameter was added to any endpoint |

Digest delivery uses the existing weekly digest. Two are also announced at
once, in the recording transaction, through the notification outbox as
`new_exposure` with aggregate type `web_endpoint`: a critical
`web_sensitive_new` and every `web_auth_lost`. The same attribution rules
and hourly budget as exposure alerts apply (a rejected, deleted,
unconfirmed or private-program origin gets no immediate alert). A
fingerprint per tenant, origin, kind and template
(`web_alert_fingerprints`) lasts the tenant's alert fingerprint lifetime, so
a flapping endpoint alerts once per lifetime; rows are purged a year and a
day after their last alert.

## Sensor contract

The verification run names templates with `scanner_config.template_ids`.
A sensor that does not know the key runs its default template set on the
URL; the template ids in the catalog must exist in the signed pack, and an
id missing from the pack produces no hit and so no finding.
