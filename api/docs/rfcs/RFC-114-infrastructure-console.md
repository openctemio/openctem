# RFC-114: Infrastructure console for self-managed installs

| | |
|---|---|
| Status | Proposed (2026-10-17). The hardened console role exists in the Ansible kit (`openctemio/openctem-ansible`, role `infra_console`). The OpenCTEM console page (section 8) is design only |
| Scope | openctem-ansible (role `infra_console`, SSH stage `DenyGroups`, later a console page package); no API or web change |
| Related | RFC-022 (platform administration console), RFC-063 (support access), RFC-105 (version check); the kit's README sections 5 (backups), 6 (upgrade) and 10 (infrastructure console) |

## 1. Summary

A self-managed OpenCTEM install has three different kinds of operator, and
each one gets its own entry point:

| Plane | Who | Where | Accounts |
|---|---|---|---|
| Application | organization members | the public host name (443, behind the tunnel) | OpenCTEM users |
| Platform console | platform administrators | `openctem_admin_host`, private networks by default (RFC-022) | OpenCTEM administrator accounts |
| **Infrastructure console** (this RFC) | host operators | one private address of the host, its own port (9090 by default) | OS accounts in `openctem-operators` |

The infrastructure console manages the **host**: disks and file systems,
services and their logs, the system journal, networking, accounts. Later it
also manages the OpenCTEM stack on the host: health, disk thresholds,
backup/restore, upgrade, log viewing and key rotation. The kit runs an
existing, maintained host console, Cockpit from the distribution archive,
and hardens it. It does not build its own. P0 is the hardened install. P1 is
one OpenCTEM page inside it.

## 2. Goals and non-goals

Goals:

- Operators can see and fix the host (a full disk, a failed unit, a
  certificate about to expire) without an SSH client, through an audited,
  two-factor entry point.
- The console is off by default and cannot be enabled insecurely: an unsafe
  setting is refused, not just warned about.
- Separation of duties: holding one plane's credentials gives no access to
  another plane.

Non-goals:

- Multi-host management. The console manages only the host it runs on.
- A browser root shell by default. The terminal is off, and turning it on
  requires recording.
- Replacing the kit. Ansible stays the way to install, change and upgrade a
  host. The console runs the kit's existing on-host commands; it does not
  provide a second, unaudited configuration path.
- Multi-tenant SaaS hosting. The provider operates those hosts, and the
  console is for self-managed installs.

## 3. Why use an existing console

A host console is root in a browser. It needs a PAM-integrated login,
privilege escalation that asks again for the password, a channel protocol
that cannot be driven cross-origin, TLS, socket activation, and per-page
content security policies. A home-grown version would need years of
hardening and a security response process of its own. Cockpit already has
these. It is packaged by Ubuntu, Debian and RHEL. It runs as an unprivileged
`cockpit-ws` behind a separate TLS front end (`cockpit-tls`, `DynamicUser`,
no network namespace). Each session runs as the signed-in user, and
escalation goes through sudo or polkit. Pages are static HTML/JS packages
with a manifest, so OpenCTEM adds one page instead of a server.

Cost: one more package set on the host (about 15 MB, no daemon until the
socket gets a connection), and its security updates arrive through the OS
updates that the kit already enables.

## 4. Threat model

**Assets:** root on the host, which means every OpenCTEM secret, the
database and the backups.

**Actors:** an internet attacker; an attacker on the admin network or VPN; a
holder of stolen operator credentials; a malicious or careless operator; a
platform administrator who tries to reach the host; a compromised
application (API, web, gateway or tunnel connector container) that tries to
reach the console.

| # | Threat | Control (P0, enforced by the role) |
|---|---|---|
| T1 | Console reached from the internet or through the tunnel | It listens on **one** address that the inventory names: private/VPN or 127.0.0.1. The role refuses 0.0.0.0, global addresses, addresses the host does not have, and container bridge addresses, so a container cannot reach it through its bridge gateway. ufw allows the port only from `infra_console_allowed_cidrs` (default `admin_cidrs`) and only to that address. The role refuses to run while ufw is inactive. The tunnel's routes name only the gateway |
| T2 | Password guessing or a stolen password | The password **and** a TOTP code (`pam_google_authenticator`). Secrets are root-owned files outside the home directory, so an operator can neither read nor delete theirs. No file means no sign-in (no `nullok`). Limits: 3 attempts per 30 s, each code works once, `MaxStartups 3:50:10` |
| T3 | Second factor bypassed through another login service | The SSH stage sets `DenyGroups openctem-operators`, because SSH asks for no code. The role refuses to run until `sshd -T` shows the rule. The local text console needs hypervisor access, which already means control of the host |
| T4 | Any local account signs in | The console's PAM stack requires membership in the `openctem-operators` group. The group failure is reported only at the end of the stack, so the prompts do not reveal which accounts exist. root and the automation account are listed in `disallowed-users`. The role refuses root, the automation account (`ansible_user`) and shared groups (`sudo`, `adm`, `docker`, `wheel`) as settings |
| T5 | Root at sign-in without re-authentication | Escalation is sudo with the operator's **own** password. The role refuses any operator who has a `NOPASSWD` rule (a cloud image default) |
| T6 | Actions nobody can account for | `pam_loginuid` ties the session to the operator. auditd logs every `execve` by each operator's login uid, including through sudo, and every change to the console settings. The terminal is off by default; turning it on requires tlog recording of the operators' terminal sessions to the journal, without keystrokes by default (they contain passwords) |
| T7 | Cross-site or DNS-rebinding use of the console channel | `Origins` is pinned to the configured address and names. `LoginTo=false` and `AllowMultiHost=false` stop the console from signing in to, or loading code from, other hosts |
| T8 | Secrets leak through automation | Enrolment runs only on the host, `sudo openctem-console-enroll <name>`, with a terminal required. It shows the QR once on that terminal. No password or TOTP secret passes through Ansible, the inventory or logs |
| T9 | Access survives offboarding | Removing an account from `infra_console_operators` removes its group membership and its TOTP secret on the next run |
| T10 | Hidden terminal taken as a boundary | It is not one: a signed-in operator can run commands through the console channel. The boundary is T2 to T6. The README and the role defaults say so |
| T11 | A platform administrator reaches the host, or the reverse | The account stores are separate: application database versus `/etc/passwd`. Nothing maps or synchronizes them. The automation account cannot be an operator |

Residual risks, stated in the README:

- Root can alter local recordings and audit logs. Ship the journal off the
  host when they must serve as evidence.
- A self-signed certificate depends on the operator comparing the printed
  fingerprint.
- Root on the host defeats every control in this table.

## 5. P0: the kit role (exists)

`playbooks/65-infra-console.yml`, role `infra_console`. It runs only with
`apply_infra_console=true`. `infra_console_state: absent` stops the console
and removes its firewall rules.

| Setting | Default | Notes |
|---|---|---|
| `infra_console_listen_address` | required | one IPv4 address of the host, private/VPN or 127.0.0.1 |
| `infra_console_port` | 9090 | not the SSH port |
| `infra_console_allowed_cidrs` | `admin_cidrs` | IPv4 CIDRs, never 0.0.0.0/0 |
| `infra_console_server_names` | `[]` | extra names (for example a private DNS name); added to `Origins` |
| `infra_console_operators` | required | OS accounts, created with no usable password or SSH key until enrolled |
| `infra_console_operator_sudo` | true | `%openctem-operators ALL=(ALL:ALL) ALL`, never NOPASSWD |
| `infra_console_terminal` | false | true requires `infra_console_session_recording` |
| `infra_console_record_input` | false | keystrokes |
| `infra_console_tls_cert` / `_key` | empty | paths on the host; empty means self-signed, with the fingerprint printed |
| `infra_console_idle_timeout_minutes` | 15 | |

What the role writes:

- a socket drop-in (`ListenStream=` reset, then `<address>:<port>`);
- `cockpit.conf` (`Origins`, `LoginTo=false`, `AllowMultiHost=false`,
  `AllowUnencrypted=false`, `MaxStartups`, `IdleTimeout`, banner, Kerberos
  negotiation off);
- the console's PAM stack (group, password, TOTP, `pam_loginuid`);
- `disallowed-users`;
- a manifest override that removes the terminal;
- a sudoers drop-in, validated with `visudo`;
- tlog settings;
- audit rules and ufw rules (one comment tag; stale rules are deleted).

After it starts the socket, the role asserts that the effective `Listen` is
exactly the configured address and port.

Tests in the kit's CI:

- render assertions on every template;
- a checks test that 22 unsafe settings (23 on a host with a container bridge) are refused and the safe ones pass;
- an Ubuntu 26.04 container end-to-end run of the role with idempotence and
  the real enrolment command, with pamtester proving each sign-in case:
  password and code accepted; wrong code, reused code, wrong password,
  password only, not enrolled, not in the group, root and offboarded refused;
- the off switch.

## 6. Port or host name

- **Default:** the private address and 9090. It needs no DNS and is not
  confused with the application ports.
- **Optional:** a name such as `system.<domain>` on **private** DNS, with
  `infra_console_server_names` and a certificate that names it. A public DNS
  record for a private address leaks the address layout and adds nothing.
- **Port 443:** possible when the host has a separate address for the
  console. The kit refuses only the SSH port.

## 7. TLS

The kit has no host certificate of its own: the edge certificate belongs to
the tunnel provider. The console therefore uses one of:

- a certificate the operator places on the host, such as one from an
  internal CA or a DNS-01 ACME client (`infra_console_tls_cert`/`_key`,
  copied to `/etc/cockpit/ws-certs.d/90-openctem.*`, key mode 0600);
- the console's self-signed certificate, with its SHA-256 fingerprint
  printed by the play so it can be compared in the browser.

The monitoring role's certificate-expiry check can cover the console
certificate later.

## 8. P1: the OpenCTEM page (design)

The page is a static package installed by the role into
`/usr/share/cockpit/openctem/` (root-owned). It adds no daemon and makes no
network calls. Each action is a **fixed** systemd unit or a fixed script
path. It runs with the console's superuser channel (`superuser: "require"`:
sudo with the operator's password) and takes an argv list, never a shell
string. The only free input is a backup identifier, which the script
validates against a strict pattern. auditd records each action through the
operator's login uid.

Manifest sketch:

```json
{
  "version": 0,
  "requires": { "cockpit": "300" },
  "conditions": [ { "path-exists": "/opt/openctem/compose.yml" } ],
  "menu": {
    "index": {
      "label": "OpenCTEM",
      "order": 5,
      "path": "index.html",
      "keywords": [ { "matches": [ "openctem", "backup", "upgrade", "stack" ] } ]
    }
  },
  "content-security-policy": "default-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'self'"
}
```

Pages (tabs of one page):

| Tab | Shows | Actions |
|---|---|---|
| Health | each container's state and health (api, web, postgres, redis, gateway, tunnel connector, job signer), the release, the last `openctem-verify` result, the latest monitor alerts (journal `openctem-monitor`) | run `openctem-verify` |
| Disk | use of `/`, the Docker data root and the backup directory, against the monitoring threshold (85% by default). A full disk once crashed PostgreSQL, so the threshold is shown before it is reached | none (cleanup stays manual and documented) |
| Backups | backups with their age, size and encryption mode; last restore drill | start `openctem-backup.service`; run the restore drill; **restore**, which needs a successful drill of that backup in the last 24 h plus typed confirmation of the host name, then runs `openctem-restore <id>` |
| Upgrade | current release, newer releases known to the version check (RFC-105), last pre-upgrade backup | shows the kit commands (rehearse with `--check --diff`, then apply). Upgrading from the host is an owner decision (D4) |
| Logs | journal and container logs for one service, with a time range and a filter | none |
| Keys | age of the generated secrets, datastore TLS certificate expiry, job-signer key age | shows the documented rotation commands. One-click rotation comes after each command has a tested rollback |

Tests for P1:

- unit tests for the page's command builders (argv only, fixed paths, the
  backup-identifier pattern);
- an end-to-end test in the kit's container harness that loads the package
  manifest and runs each action against a scratch stack.

## 9. Packaging

| Distribution | Packages | Notes |
|---|---|---|
| Ubuntu 26.04 | cockpit-ws/system/bridge/storaged 360 (universe), tlog 14, libpam-google-authenticator, qrencode | the kit's target |
| Ubuntu 24.04 | 314 in the release, newer versions in backports; tlog 14 | works; the kit's Docker pins are the 26.04 limit |
| Debian 12/13 | in main; backports carry newer versions | not a kit target |
| RHEL 9/10 | in the base OS, with a session-recording page; SELinux needs `websm_port_t` for a non-default port; firewalld instead of ufw | not a kit target. A port of the role would swap ufw for firewalld and add the SELinux port |

No session-recording viewer is packaged for Ubuntu. Recordings are replayed
with `tlog-play` from the journal. The P1 page can list them.

## 10. Alternatives considered

- **Build a host console into OpenCTEM.** Rejected: it would give the
  application root on the host, merge the application and infrastructure
  planes, and put a root shell under our own security maintenance.
- **SSH only, with no web console.** Still supported; it is the default
  while the console is off. The console adds a two-factor, audited path for
  operators who do not use SSH, and a place for the OpenCTEM page.
- **Put the console behind the gateway or tunnel with the application.**
  Rejected: that exposes a root entry point on the public edge, and the
  edge's identity check would become the only factor.
- **Run the console in a container that reaches the host over SSH.**
  Rejected for the kit: it adds an SSH password path on the host that
  bypasses T3.

## 11. Owner decisions

| # | Decision | Recommendation |
|---|---|---|
| D1 | Default port and name | 9090 on a private address; a private DNS name is optional |
| D2 | TLS default | self-signed with the fingerprint printed; your own certificate recommended |
| D3 | Operators get sudo | yes, with their own password (otherwise the console is read-only) |
| D4 | Upgrade from the console | no for P1: it shows the kit commands. Running the kit on the host would put the controller's inventory on the host |
| D5 | Terminal default | off; on requires recording; keystroke recording off |
| D6 | Recovery codes for the second factor | none: an administrator with SSH re-enrols the operator. That keeps the root-only secret file as the single source |
| D7 | Restore from the console | only after a successful drill of the same backup and typed confirmation |
