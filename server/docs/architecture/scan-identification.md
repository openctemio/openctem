# Scan identification markers

Status: platform, organization, program and sensor-local layers, the query
parameter, User-Agent rotation, required identification and the run-detail
"Sent with" view shipped; signed scan token and secret WAF token planned (see
"Planned").

A target's WAF, SIEM and logs need to tell an organization's authorized scan
traffic apart from everything else. Three things identify it:

1. **Scanner addresses**: the addresses the organization's scans leave from,
   observed by the platform itself (Settings > Scanning > Proxies, "Scanner
   addresses"; [sensor proxies](sensor-proxies.md)).
2. **User-Agent, request headers and a query parameter** every HTTP request
   of a scan carries (this page).
3. (Planned) a **signed scan token** a target can verify, so a copied static
   header cannot pass for an authorized scan.

## What is configured

| Marker | Shape |
|---|---|
| User-Agent | at most 256 printable ASCII characters |
| User-Agent rotation list | instead of the single User-Agent (a layer sets one or the other, never both): at most 200 distinct values, each 1-256 printable ASCII characters without a leading or trailing space (contract `identity.CheckUserAgents`) |
| Query parameter | one `{name, value}` added to every request URL; each 1-64 of letters, digits and `. _ ~ -` (no percent-encoding needed anywhere in a URL) |
| Required identification | a switch: every request must carry a header or the query parameter |
| Request headers | a list of `{name, value}`. The name is free: any HTTP token (letters, digits and ``!#$%&'*+-.^_`|~``, no space or colon), at most 64 characters, case-insensitive, no duplicates. The value is printable ASCII (no line break or other control character), at most 200 characters |

Refused names at every layer: `Host`, `Content-Length`, `Transfer-Encoding`,
`Connection`, `Keep-Alive`, `TE`, `Trailer`, `Upgrade`, every `Proxy-*`, and
the credential headers `Authorization` and `Cookie`. The rules live in
`pkg/domain/scanident` and match the sensor's (sdk-go
`core.OrgHTTPPolicy.Validate`), so a value the platform accepts is one the
sensor accepts.

## Layers and merge

Markers come from layers that are **merged, never replaced**: every distinct
header name is kept. On a clash (names compare case-insensitively) the more
specific layer wins, except over an enforced platform header:

| Precedence (highest first) | Layer | Where | Bound |
|---|---|---|---|
| 1 | platform, enforced | Console > System > Scan identification | 4 headers |
| 2 | bug-bounty program rules | the program ([bounty programs](bounty-programs.md)) | 10 |
| 3 | sensor host owner (planned) | the sensor's local policy | |
| 4 | organization | Settings > Scanning > Scan identification | 6 headers |
| 5 | platform default | Console > System > Scan identification | (in the 4) |

The User-Agent follows the same order: an enforced platform User-Agent, else a
program's, else the organization's, else the platform default. A layer's
User-Agent setting is its rotation list, else its single value; **the winning
layer's list is used whole, never merged** with another layer's (a union of
fingerprints would make no sense). It is locked (the sensor-local layer cannot
replace it) when the platform enforces it or a program sets it. The query
parameter follows the enforced platform, then the organization, then the
platform default (programs set none); it is locked only when enforced.
Required identification is the logical OR of the platform, the organization
and the job's programs: a lower layer can never clear it. A job carries
at most 10 headers after the merge (the sensor refuses more): the platform
and organization bounds add up to 10, and a program whose headers would push
a job over fails that job at claim with `PROGRAM_RULES_CONFLICT`.

## Flow

1. A platform administrator saves the platform layer: `PUT
   /api/v1/admin/settings/scan-identification` (`platform.settings.general.write`,
   step-up, a reason; audited, every administrator notified; compare-and-swap
   on `version`). Any administrator reads it.
   Body: `user_agent` or `user_agents`, `user_agent_enforced` (locks the
   value or the list), `headers`, `query`, `query_enforced`,
   `identification_required`.
2. An organization owner saves the organization layer in the security settings
   section (`PATCH /api/v1/tenants/{tenant}/settings/security`,
   `tool_http_user_agent` or `tool_http_user_agents`, `tool_http_headers`,
   `tool_http_query`, `tool_http_identification_required`; owner, `settings:write`,
   step-up, audited, `If-Match`). `GET /settings` also returns the platform
   layer (`security.platform_scan_identification`) so the page can show the
   effective set.
   A bug-bounty program's rules carry `user_agent` or `user_agents` and
   `identification_required` (new programs default to on in the console;
   programs saved before keep it off). Imports and re-imports are audited
   with the identification rules in force.
3. When a sensor claims a scan, retest or validate job, the command service
   merges the platform and organization layers of **the job's own
   organization** into the job's `http_policy` on the delivered copy; the
   stored command never changes and any value a command's creator wrote there
   is replaced. Program rules go over it. The job signature covers the payload.
   Fields: `headers`, `locked_headers`, `user_agent`, `user_agent_locked`,
   `query`, `identification_required`, and, only when the list in force has
   more than one value, `user_agents` and `user_agent_key`. `user_agent` is
   then the list's first value, so a sensor without rotation still sends a
   value of the list. `user_agent_key` is the job's `scan_run_id` (the command
   id for a job outside a run).
4. sdk-go core applies the identity in one place (the tool host admission):
   each tool gets it through its own flags (nuclei `-header`, httpx and katana
   `-H`, exec tools through argv placeholders) and in-process tools through
   `ctx.HTTP()`. The sensor host owner's local layer (`http.headers`,
   `http.user_agent`) is merged in, never over a locked name or a locked
   User-Agent. Nothing intercepts TLS.
5. With the result, the sensor reports what each task's requests carried
   (result metadata `http_identity`): the User-Agent and its source, the
   rotation pool size, every header with its source (`job`, `job_locked`,
   `sensor`) and whether it was applied (with the reason when not), the query
   parameter, whether identification was required, and the carrier (`tool` or
   `forwarder`). The platform parses it defensively (bounded, single-line,
   values of secret-looking names masked again) into the step's
   `sensor_settings.sent_with` and shows it on the run detail as "Sent with".
   It is display only: nothing decides anything from it.

## User-Agent rotation

A layer may give a list of up to 200 values instead of one User-Agent. Each
target host of a run gets one value: contract `identity.SelectUserAgent`
computes HMAC-SHA-256 keyed by the run key (`user_agent_key`) over a fixed
label and the canonical host (lower-case, no port, brackets or trailing dot),
modulo the list length. The choice is sticky: every request of one run to one
host, from every task, carries the same value, so a session never changes its
fingerprint half way; different runs and hosts spread evenly. Rotation alone
needs no sensor gate: a sensor that predates it sends `user_agent`, the
list's first value.

## Required identification

When the platform, the organization or a covering program requires it, the
job's requests must carry the identification headers and the query parameter
on every request. The platform fails closed at claim:

1. A job that requires identification but whose effective set has no header
   and no query parameter fails with `IDENTIFICATION_REQUIRED_MISSING` and a
   message naming the fix (set a header or query parameter at the platform,
   organization or program layer). It is never delivered.
2. A sensor that does not report `http.identity.required@1` does not get the
   job: it waits for one that does (decided by what the sensor reports, never
   by its version). A sensor that predates the field would drop the
   requirement silently. A claim by id answers `IDENTIFICATION_REQUIRED_UNSUPPORTED`.
3. A layer that cannot be read withholds the job.

On the sensor, per task:

| Tool can carry it | Sandbox confines network | Result |
|---|---|---|
| yes (`features.http_identity` / argv placeholders; `features.http_query` / `{{http.query:-flag}}`) | any | the tool carries it |
| no | yes | the forwarder adds it to every HTTP/1.x request and refuses anything else |
| no | no | task refused (`refused_by_policy`), zero requests |

Non-HTTP tasks (port scan, DNS) are unaffected.

## Security

- **Injection**: token names and printable-ASCII values (no CR or LF) are
  checked in the web form, the API and again by the sensor before a tool runs.
- **Transport and credentials**: the refused names above; credentials never
  travel as a plain marker.
- **Tenant isolation**: a job carries only its own organization's layer, even
  when one delivery to a shared sensor holds jobs of several organizations
  (`TestDeliverIdentityIsPerJobTenant`,
  `TestIdentityRotationAndRequiredArePerJobTenant`: another organization's
  list, query parameter and requirement never reach a job, and its
  requirement never holds another organization's job back).
- **Rotation and misuse**: rotation is for authorized testing inside the
  organization's enforced scope (the scope gates are unchanged). It never
  weakens attribution: the headers and the query parameter travel with every
  value of the list, and required identification is enforced fail closed, so
  a list cannot be used to hide scan traffic among ordinary browsers.
- **Old sensors**: a job that requires identification is withheld from a
  sensor that does not report `http.identity.required@1`.
- **Sensor reports are untrusted**: `http_identity` is bounded, cleaned to
  single lines, secret-looking values are masked again, and it is only shown.
- **No default disclosure**: nothing is sent unless configured; no default
  names the organization.
- **Static markers are copyable**: anyone who learns a header can send it.
  Use markers to tag scan traffic in logs, or allow it together with the
  scanner addresses; never let a static header alone bypass a WAF.
- **Audit**: platform changes write an admin audit row with the reason and the
  old and new values (markers are not secrets); organization changes are part
  of the security settings audit (turning required identification off is
  graded high); program imports and re-imports record the identification
  rules in force.

## Simplest path

Each of the three pages has one main control, "Require identification on
every request", with safe defaults (nothing is sent without it). Rotation,
the query parameter and (on the platform) the Enforced locks are folded under
"Advanced". Values a higher layer locks are shown read-only with their source;
required with no header and no query parameter anywhere shows an error with
the action that fixes it.

## Planned

- Signed scan token (short-lived, bound to the job's hosts, verifiable with a
  published key).
- Secret WAF token (write-only, may use a credential header name).
- Scan profile and asset group overrides.
