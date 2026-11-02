# Scan identification markers

Status: platform and organization layers shipped; sensor-local layer, query
parameter, run-detail view, signed scan token and secret WAF token planned
(see "Planned").

A target's WAF, SIEM and logs need to tell an organization's authorized scan
traffic apart from everything else. Three things identify it:

1. **Scanner addresses**: the addresses the organization's scans leave from,
   observed by the platform itself (Settings > Scanning > Proxies, "Scanner
   addresses"; [sensor proxies](sensor-proxies.md)).
2. **User-Agent and request headers** every HTTP request of a scan carries
   (this page).
3. (Planned) a **signed scan token** a target can verify, so a copied static
   header cannot pass for an authorized scan.

## What is configured

| Marker | Shape |
|---|---|
| User-Agent | at most 256 printable ASCII characters |
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
program's, else the organization's, else the platform default. A job carries
at most 10 headers after the merge (the sensor refuses more): the platform
and organization bounds add up to 10, and a program whose headers would push
a job over fails that job at claim with `PROGRAM_RULES_CONFLICT`.

## Flow

1. A platform administrator saves the platform layer: `PUT
   /api/v1/admin/settings/scan-identification` (`platform.settings.general.write`,
   step-up, a reason; audited, every administrator notified; compare-and-swap
   on `version`). Any administrator reads it.
2. An organization owner saves the organization layer in the security settings
   section (`PATCH /api/v1/tenants/{tenant}/settings/security`,
   `tool_http_user_agent` and `tool_http_headers`; owner, `settings:write`,
   step-up, audited, `If-Match`). `GET /settings` also returns the platform
   layer (`security.platform_scan_identification`) so the page can show the
   effective set.
3. When a sensor claims a scan, retest or validate job, the command service
   merges the platform and organization layers of **the job's own
   organization** into the job's `http_policy` (`headers`, `user_agent`,
   `locked_headers`, `user_agent_locked`) on the delivered copy; the stored
   command never changes and any value a command's creator wrote there is
   replaced. Program rules go over it. The job signature covers the payload.
4. sdk-go core applies the identity in one place (the tool host admission):
   each tool gets it through its own flags (nuclei `-header`, httpx and katana
   `-H`, exec tools through argv placeholders) and in-process tools through
   `ctx.HTTP()`. A tool that cannot carry headers is refused while an identity
   applies (tools declare `features.http_identity`). Nothing intercepts TLS
   and the forwarder never injects headers.

## Security

- **Injection**: token names and printable-ASCII values (no CR or LF) are
  checked in the web form, the API and again by the sensor before a tool runs.
- **Transport and credentials**: the refused names above; credentials never
  travel as a plain marker.
- **Tenant isolation**: a job carries only its own organization's layer, even
  when one delivery to a shared sensor holds jobs of several organizations
  (`TestDeliverIdentityIsPerJobTenant`).
- **No default disclosure**: nothing is sent unless configured; no default
  names the organization.
- **Static markers are copyable**: anyone who learns a header can send it.
  Use markers to tag scan traffic in logs, or allow it together with the
  scanner addresses; never let a static header alone bypass a WAF.
- **Audit**: platform changes write an admin audit row with the reason and the
  old and new values (markers are not secrets); organization changes are part
  of the security settings audit.

## Planned

- Sensor-local layer (the host owner's headers, applied to every job the
  sensor runs, never over a locked name) and the applied set reported back.
- Query parameter marker, once tools declare support for it.
- Run detail "Sent with" block listing each header with its layer.
- Signed scan token (short-lived, bound to the job's hosts, verifiable with a
  published key).
- Secret WAF token (write-only, may use a credential header name).
- Scan profile and asset group overrides.
