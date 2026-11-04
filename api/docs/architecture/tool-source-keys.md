# Tool source keys

Some scan tools query third-party sources that need a key: subfinder's
passive subdomain sources (securitytrails, shodan, censys, virustotal and
about forty more). An organization stores its own keys in the console
(Settings, Scanning, Tool source keys); the platform delivers them to a
sensor only for a task of that organization's job, for the job's tool. The
platform itself never calls a source.

## Storage

- Table `tool_source_keys`: one row per organization and source
  (`UNIQUE (tenant_id, source)`), the key as AES-GCM ciphertext under
  `APP_ENCRYPTION_KEY` (`key_enc`, in the rekey registry), its last four
  characters (none for a key shorter than 12), an enabled switch, who changed
  it and when, and when it was last delivered.
- The catalog of sources is the platform's (`pkg/domain/toolsource`): a
  source id is the credential name the tool's manifest declares
  (`permissions.credentials` in its tool.yaml), with its format (`key`, or a
  `pair` such as `TOKEN:ORG_ID` for censys). Only catalog sources are stored.
- A key is 1 to 1024 visible ASCII characters without spaces, with a secret
  part of at least 8; a pair has exactly one colon between two non-empty
  parts. Error messages never repeat the value. Only the tail of the secret
  part is shown (never a user name or app id).
- Sources whose first part names where the tool connects accept their own
  service only: intelx `HOST:KEY` with HOST under `intelx.io`, zoomeye
  `HOST:KEY` with HOST `zoomeye.ai|hk|org`, redhuntlabs
  `https://HOST/PATH:KEY` with HOST under `redhuntlabs.com` (https, no port,
  user information, query or fragment). IP addresses and any other host are
  refused, so a tenant cannot point a shared sensor at an address of its
  choice; the sensor checks the same rule again before it writes the file.

## Console API

| Route | Permission |
|---|---|
| `GET /api/v1/tool-sources` | `scans:secret_store:read` |
| `PUT /api/v1/tool-sources/{source}/key` `{value}` (set or replace) | `scans:secret_store:write`, owner/admin, step-up, credential factor |
| `PATCH /api/v1/tool-sources/{source}` `{enabled}` | `scans:secret_store:write`, owner/admin, step-up, credential factor |
| `DELETE /api/v1/tool-sources/{source}/key` | `scans:secret_store:delete`, owner/admin, step-up |

No answer carries a key. Every change is audited (`tool_source_key.set`,
`.enabled`, `.disabled`, `.deleted`), with the source and last four
characters only.

## Delivery to a sensor

`POST /api/v2/sensor/commands/{command_id}/tool-credentials` `{tool}` (v2
HTTPS only, never protocol v3), asked by the sensor once per task of a tool
whose manifest declares credentials:

1. The organization is the command's: an organization sensor reads commands
   of its own tenant only; a shared sensor reads only the shared job it
   holds (`HeldSharedJob`). Nothing the sensor sends names a tenant.
2. The sensor must hold the command's live lease: its id, the lease epoch it
   states, status acknowledged or running.
3. The tool must be the job's tool, or implement the capability the job
   names (`discover.subdomains@1` for subfinder), and have catalog sources.
4. An organization sensor gets keys only when its grant is trusted (an
   unreadable grant gives none). A shared sensor is the platform's own.
5. Only the organization's enabled keys of that tool's sources are returned;
   one that cannot be decrypted is skipped.

Any refusal is `command_not_found`, the same for another tenant's command and
one that does not exist. The answer is `Cache-Control: no-store`, is never
logged and nothing is stored on the command; the delivery is audited
(`tool_source_key.delivered`: sources, sensor, command) and marks the keys
used.

`local_fallback` in the answer is true on an organization's own sensor and
false on a shared sensor. The sensor (sdk-go tool host) merges per name: the
organization's key wins; a key the sensor's operator configured fills a name
the organization left unset only when `local_fallback` is true, so a shared
sensor never spends its operator's keys on an organization's task.

On the sensor, the keys reach the tool in the task's run message only, are on
the task's redaction list and are dropped when the task ends. subfinder
writes them into a provider configuration in the task's own directory (mode
0600, removed with it) and runs with `-pc` on that file, never with a key on
its command line or in its environment.

## Threat model

| Threat | Control |
|---|---|
| A scan of organization B uses A's key | Keys are read by the command's tenant at delivery; repository queries are tenant-scoped |
| A sensor of A fetches keys for B's command | Lease holder only; an organization sensor never reads another tenant's command |
| A shared sensor mixes organizations | One fetch per task under that task's lease; no cache across tasks; the task's private directory |
| Keys in logs, results or the job | Not in the signed job, payload, outbox or result; redaction list; no-store; write-only API |
| An untrusted sensor receives keys | Only trusted organization sensors; unreadable grant gives none |
| Database dump | AES-GCM ciphertext; rekey registry |
| A tenant points a sensor at an internal address through a key | Host and URL parts restricted to the source's own service, checked on save and again on the sensor |
| A compromised trusted organization sensor | It can fetch its own organization's keys for the commands it holds, nothing more; revoke or distrust the sensor and rotate the keys |
| Ciphertext moved between rows | Accepted: like every stored secret today the ciphertext is not bound to its row (no associated data) |

Not yet: per-source usage reports and quota, a Test button (run by a sensor),
platform-held keys for organizations that opt in, and keys for other tools
(nuclei, search and leak sources).
