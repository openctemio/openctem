# RFC-114: System page and host operations for self-managed installs

| | |
|---|---|
| Status | Proposed (2026-10-17) |
| Scope | API (`GET /api/v1/admin/system`, a watcher), the platform console (System page), docs. The kit (`openctemio/openctem-ansible`) gets one optional, documented recipe |
| Related | RFC-022 (platform administration console), RFC-063 (support access), RFC-105 (version check); the monitoring guide (`docs/operations/monitoring.md`); the kit's README (backups, upgrade) |

## 1. Summary

A self-managed install needs its operator to see the state of the host's
essentials at a glance and to be told early when something degrades: a disk
filling up, a stale backup, a certificate about to expire. It does not need a
second, browser-based root entry point.

Decision (owner, 2026-10-17): **the kit ships no host console.**

| Need | Where it lives |
|---|---|
| See service health, storage, backup age, certificate expiry, version | a **read-only System page in the platform console** (this RFC) |
| Be told when a threshold is crossed | the **existing notifications**: the system mailer to the active platform administrators, a WARN log line with a stable `alert` field, and metrics |
| Back up, restore, upgrade, rotate keys | the **kit's command line over SSH**, as today. Nothing privileged runs from a browser |
| A web UI for the host itself (disks, units, journal) | **optional**: Cockpit, as a documented recipe (appendix A), never installed by the kit |

The System page is for platform administrators only. It is not part of the
tenant UI, and an organization user's token never reaches it.

## 2. Goals and non-goals

Goals:

- One page shows whether the stack is healthy and whether the host is about to
  run out of room, with no extra monitoring stack.
- Everything on it is aggregate-only: no tenant data, no secrets, no file
  paths beyond configured names.
- Reading it needs no step-up and changes nothing.
- A threshold crossing reaches an administrator without anyone opening the page.

Non-goals:

- Any action: no restart, restore, upgrade, backup start or key rotation from
  the page. Those stay in the kit.
- Host administration (accounts, packages, firewall). That is SSH and the kit.
- Replacing the monitoring guide's Prometheus alerts. The page and the
  watcher are the built-in minimum for installs that have none.
- Root in a browser, by default or through OpenCTEM.

## 3. Why no host console in the kit

A host console is root in a browser. Hardening it properly needs a
PAM-integrated login with a second factor, re-authentication on escalation, an
origin-pinned channel, a private listener that no container can reach,
recording and audit, and a security response process for the console package.
The kit would own all of that for a feature most installs do not need, and a
mistake there is root on the host: every secret, the database and the backups.
SSH with key-only login, which the kit already hardens, covers the privileged
work. The System page covers the visibility that operators asked for, without
holding any privilege on the host.

## 4. The System page

Route: `GET /api/v1/admin/system`, registered with the console's admin
middlewares. Every console role may read it, including the read-only role. The
page is `/admin/system` in the platform console, under Operations (it adds
the host essentials that Operations does not show).

### 4.1 Content

| Section | Source | Notes |
|---|---|---|
| Services | api (itself), postgres (ping), redis (ping), web and gateway (an HTTP GET to the configured health URL, `SYSTEM_WEB_HEALTH_URL`, `SYSTEM_GATEWAY_HEALTH_URL`), connected sensors (active sensors by health, from the same read as Operations) | an unset URL reports "not configured", not an error |
| Storage | free and used bytes of each configured data path (`statfs`), and the database size (`pg_database_size` of the connected database) | thresholds: warning below 20% free, critical below 10% |
| Backup | time of the last successful backup, from the backup status file the monitoring guide already defines (`openctem_backup_last_success_timestamp_seconds`) | warning when older than 26 h; "not reported" when the file is not configured or empty |
| Certificates | expiry of the sensor CA and of each configured TLS certificate file | warning below 30 days, critical below 7 days |
| Version | running version and the version-check result (RFC-105): latest release, update available, advisories affecting this build | |

Configuration (all optional, set by the operator, never by a request):

| Variable | Meaning |
|---|---|
| `SYSTEM_STORAGE_PATHS` | `name=path` list of directories to measure. Default: the attachments directory and the sensor CA directory, when local |
| `SYSTEM_BACKUP_STATUS_FILE` | the backup status file (mount it read-only into the API) |
| `SYSTEM_TLS_CERT_FILES` | `name=path` list of PEM certificate files to check |
| `SYSTEM_WEB_HEALTH_URL`, `SYSTEM_GATEWAY_HEALTH_URL` | internal health URLs |
| `SYSTEM_WATCH_INTERVAL` | how often the watcher evaluates (default 5 minutes) |

### 4.2 Alerts

A background watcher evaluates the same snapshot on an interval. It
sets metrics (`openctem_system_storage_free_ratio{volume}`,
`openctem_system_backup_age_seconds`,
`openctem_system_certificate_expiry_seconds{name}`, and a `..._level` gauge per
check: 0 ok, 1 warning, 2 critical), writes a WARN line with
`alert=system_<check>` on a level change, and emails the active platform
administrators through the system SMTP sender when a check gets worse. The
same check does not email again within 24 hours unless it gets worse. When SMTP
is not configured the log line and the metrics are the alert, as for
break-glass sign-ins.

### 4.3 Threat model

**Assets:** infrastructure facts about the installation (disk sizes, database
size, certificate expiry, internal health URLs) that help an attacker pick a
moment or a target.

| # | Threat | Control |
|---|---|---|
| T1 | An organization user reads it | admin routes accept console sessions only; a tenant token is refused (401), tested |
| T2 | The page leaks tenant data or secrets | the response holds counts, byte sizes, timestamps, status words and operator-chosen names. No path, URL, hostname or error text leaves the server: a failing probe reports a fixed code (`unreachable`, `unhealthy`, `unreadable`) |
| T3 | The health probes become a request forger | the URLs come from the operator's environment, not from any request; a probe sends one GET without redirects, a short timeout, and discards the body. Only http(s) URLs are accepted at startup |
| T4 | A configured path escapes its purpose | the paths are operator-set; only `statfs` and a bounded read of one status file and PEM certificates happen. A status file over 64 KiB is refused |
| T5 | The page is used to act on the host | it holds no action. The watcher only reads and sends mail |
| T6 | Mail floods the administrators | one email per check per 24 h unless it worsens |

## 5. Privileged operations stay in the kit

Backup, restore (after a drill), upgrade and key rotation run from the
controller with the kit over SSH, which the kit already hardens (key-only
login, no root login). Each is audited by the kit and needs the operator's SSH
identity. The System page shows the outcome (backup age, version, certificate
expiry); it never starts them. A one-click action from the browser is out of
scope and would need its own RFC with a threat model for a root-capable channel.

## 6. Alternatives considered

- **A host console in the kit** (a packaged host management console behind a
  private port with a second factor). Rejected for the reasons in section 3.
- **A privileged agent that the System page calls** (to start backups or
  upgrades). Rejected: it puts a root-capable endpoint behind the application,
  so an application compromise becomes a host compromise.
- **Only metrics and alerts, no page.** Not enough for installs without a
  monitoring stack; the page and the watcher are small and read-only.
- **Reading free space through node metrics.** Needs the monitoring stack. The
  API measures the volumes it can see, which are the ones that hurt the
  application when they fill.

## Appendix A. Optional recipe: a host console

This is documentation only. The kit does not install, configure or test it. If
an operator wants a web UI for the host, a packaged host console can be
installed by hand, under these conditions:

- **Opt-in.** Install it deliberately; remove it when not needed.
- **Private address.** Bind it to one private or VPN address (or 127.0.0.1
  with an SSH tunnel), never to 0.0.0.0, never through the tunnel or gateway,
  and allow its port in the firewall only from the admin network.
- **Second factor.** Require a password and a one-time code in its PAM stack
  (a TOTP module), restrict sign-in to a dedicated operators group, deny that
  group in SSH (SSH asks for no code), and refuse accounts with passwordless
  sudo.
- **Terminal off.** Remove the in-browser terminal page. A signed-in operator
  can still run commands through the console channel, so the boundary is the
  login and the audit, not the hidden page.
- **Record.** Keep auditd on for those accounts and ship the journal off the
  host.

Anything stronger (session recording, TLS from an internal CA, origin pinning)
is the operator's to add; follow the package's own hardening guide.
