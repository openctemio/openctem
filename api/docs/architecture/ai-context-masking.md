# AI context masking

Status: shipped (masker, data classes, bundle builder, run map store, policy
and preview API). Planned: the AI analysis executor that uses the bundle and
the run map for every AI result, the console page, and resolution at the tool
boundary of an analyst worker's sandbox.

Every context the platform sends to an AI model is pseudonymised. The model
sees typed placeholders instead of hosts, addresses, e-mail addresses, user
and organization names, URL parameters and ticket ids; secrets never reach it
at all. The platform alone keeps the mapping and turns the model's output
back into real values. Key code: `pkg/aimask` (masker), `internal/app/aipolicy/classify.go`
(data classes), `internal/app/aibundle` (bundle builder),
`internal/app/aimaskmap` and `ai_mask_maps` (run maps),
`internal/app/tenantai/masking.go` (policy and preview).

## Placeholders

| Value | Placeholder | Reversible | Found by | Structure kept |
|---|---|---|---|---|
| Registrable domain | `DOMAIN_<s>` | yes | subject identifiers, host pattern checked against the public suffix list | labels in front stay (`api.DOMAIN_K3F9QA`) unless the policy masks them |
| Internal host (single label, `.local`, `.internal`, `.corp`, `.lan`, `.home`, `.intranet`, `.localdomain`, `.private`, `.test`) | `HOST_<s>` | yes | subject identifiers, pattern | none |
| IP address | `IP_PUB_<s>`, `IP_PRIV_<s>`, `IP_LOOP_<s>`, `IP_LINK_<s>`, `IP6_...` | yes | parse | the address class; for each network in the bundle a trusted fact `IP_PRIV_x is in CIDR_PRIV_y/24` |
| Network | `CIDR_PUB_<s>/n`, `CIDR_PRIV_<s>/n` | yes | parse | prefix length |
| E-mail address | `EMAIL_<s>` | yes | pattern | none |
| User name | `USER_<s>` | yes | the subject's own people only (seeded) | none |
| URL path id, query value | `ID_<s>`, `PARAM_<s>` | yes | URL parse: numeric, UUID, long hex or token-like segments; every query value | scheme, path shape, query keys |
| Organization, customer, term | `ORG_<s>` | yes | the organization's name and the terms the administrator adds | none |
| Ticket id | `TICKET_<s>` | yes | `KEY-123` shape, public identifier schemes (CVE, CWE, GHSA, vendor advisories, algorithm and standard names) excluded | none |
| Secret: credential, token, private key, cookie, session id, `Authorization` value, URL password, secret query value | `SECRET_<n>` | **never** | the shared secret patterns (`pkg/safetext`), PEM blocks, secret query keys | a trusted fact `SECRET_n: <type>, <length> chars` |
| Input text that already looks like a placeholder | `LIT_<s>` | yes (back to the literal) | the placeholder pattern, matched before anything else | the model never sees a placeholder the platform did not issue |

`<s>` is derived per run: the first characters of `HMAC-SHA256(run key, prefix
|| 0x00 || normalised value)` in base32 (always holding a digit, so a
placeholder is never an ordinary word), lengthened on a collision inside the
run. The run key is 32 random bytes that never leave the platform. Same
value, same placeholder within a run; the same value is a different
placeholder in another run or another organization; a placeholder says
nothing about its value.

Detectors run in a fixed priority on the original text, and a span claimed by
one is never touched by a later one: placeholder-shaped input, private key
blocks, URLs (host, ids, parameters, secret parameters), other secrets,
seeded subject identifiers (longest first, word bounded, case-insensitive),
e-mail addresses, networks, addresses, host names, ticket ids. File names
whose suffix is also a country domain (`app.py`, `README.md`) and dotted
version numbers are left alone in free text.

## Data classes

Every bundle field has a class (`internal/app/aipolicy/classify.go`); a field
missing from the registry is tenant-only and never sent.

| Class | Fields |
|---|---|
| public | CVE, CWE, OWASP, KEV, EPSS |
| internal | title, description, severity, CVSS, source, tool, file and line, exposure, data exposure, compliance, priority class and reason, asset name, type, criticality, environment, exposure |
| restricted | code snippet |
| tenant_only | anything not registered |

The use case's ceiling decides which fields go; the others are listed as
withheld. Internal fields are masked under the organization's policy;
restricted fields are always masked with every class on. A leaked-secret
finding never sends its snippet, whatever the ceiling. The AI egress policy
(campaign TLP limit, campaign AI switch) is checked first: a refused finding
gets no bundle at all.

## The bundle

`aibundle.Builder.Build` returns the masked fields, the prompt section
(platform facts first, then the fields; untrusted text inside a per-request
nonce fence after Unicode normalisation and the known-injection filter shared
with AI triage in `internal/app/aiprompt`), a digest (`sha256` over the
canonical JSON of the masked fields and facts), the fields sent and withheld,
the data class, whether injection markers were found, and the masker that
holds the mapping.

## Run maps

`ai_mask_maps` keeps one row per run: the run key and the reversible
placeholder map, each AES-GCM encrypted with `APP_ENCRYPTION_KEY` (in the
rekey registry). Rows are scoped by organization (a run id of another
organization is not found), expire after `AI_MASK_MAP_TTL` (default 7 days)
and are purged hourly by `ai-mask-map-purge`; they go with the organization.
Secrets are never in the map. Nothing sends a map to a model or a worker.

## Turning output back into real values

`aimask.Unmasker.Unmask` replaces every issued placeholder in model output
with its value. A placeholder the run never issued (forged, invented, or
another run's) stays visible as text and is reported: the caller stores the
result for a person's review and never applies it. `UnmaskStrict` refuses any
unknown placeholder, for a typed field that must hold a real value.
`SECRET_n` is never resolved. `LIT_x` resolves back to the literal input.

## Tool boundary (planned for analyst workers)

The model sees and passes placeholders. The signed investigation grant will
carry, for the subject only, bindings from the exact masked form to the real
target (`db01.corp.DOMAIN_K3F9QA -> db01.corp.example.com`,
`Masker.BindingsFor`). The tool boundary resolves a masked target only when
that whole form is bound (`aimask.ResolveForGrant`): another host under the
same domain placeholder, a raw value, another run's placeholder, a secret or
a literal is refused before any connection, so the model never gets a raw
target and cannot redirect a tool.

## Policy and preview

Settings > AI > Data masking (API):

| Route | Gate | What |
|---|---|---|
| `GET /api/v1/organization/settings/ai/masking` | owner or admin, `settings:read` | classes, label switch, terms |
| `PUT /api/v1/organization/settings/ai/masking` | owner or admin, `settings:write`, recent sign-in | replace the policy; audited `ai_settings.masking_updated` (high), `loosened` flags a change that masks less; term values are counted, never logged |
| `POST /api/v1/organization/settings/ai/masking/preview` | owner or admin, `settings:read` | the masked bundle of one finding the caller can read (data scope and pentest campaign rules), placeholders with their class only, fields sent and withheld; nothing goes to a model and the map is discarded; audited `ai_settings.masking_previewed` |

Classes an administrator may leave readable in internal data: `hosts`, `ips`,
`emails`, `users`, `url_params`, `orgs`, `tickets`. Secrets and restricted data
are not configurable. Up to 200 terms of 3 to 128 characters. The stored form
lists the classes turned off, so a class added later is masked by default.

## Threat model

| Threat | Control |
|---|---|
| A provider or a provider-side leak exposes the organization's hosts and people | values never leave the platform; the key and map stay encrypted on the platform |
| Linking placeholders across runs or organizations | per-run keyed hash; no global dictionary |
| A secret in finding text reaches a model or comes back in output | secrets replaced before sending, never kept in the map, never resolved |
| Hostile input forges a placeholder to make the platform resolve it (token injection) | placeholder-shaped input becomes `LIT_x` before masking |
| The model invents a placeholder or reuses another run's | unknown placeholders are reported and never resolved; strict fields refuse them |
| The model redirects a tool to another host | only the grant's exact bound forms resolve at the tool boundary |
| One organization reads another's map or previews another's finding | every query scoped by organization; preview uses the caller's own data scope (404 otherwise) |
| An administrator quietly turns masking off | recent sign-in, high-severity audit row flagged `loosened` |

## Residual risk

- **Context re-identification**: surrounding text (product names, versions,
  paths, error messages, a rare combination of technologies) can still point
  to an organization for someone who knows it. Masking lowers the risk; the
  data class ceiling and the organization's consent stay the main controls.
- Subdomain labels are kept by default (`payroll.DOMAIN_x`); the label switch
  masks them.
- Pattern detection misses formats it does not know (a host inside a base64
  blob, a name written unusually). Seeded subject identifiers are always
  masked; free text is best effort.
- Lengths and counts stay visible (number of hosts, a secret's length).
