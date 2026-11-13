# RFC-060: Tool network confinement, verified built-ins and the tool override surface

| | |
|---|---|
| Status | Proposed (owner 2026-10-08: "the tool SDK must be secure", and "a developer must be able to override fields such as the User-Agent; support flexibility as much as possible") |
| Authors | Platform team |
| Related | RFC-034 (egress profiles, in-sensor forwarder), RFC-040 (mutual distrust), RFC-054 (scope model), RFC-055 (tool contract), RFC-056 (web scope), RFC-061 (content packs) |
| Code (today) | sdk-go `pkg/sensorkit/executor` (process sandbox), `pkg/sensorkit/toolhost` (tool host), `internal/toolrt/http.go` (`ctx.HTTP()`), `pkg/conformance` (kit); api `pkg/domain/sensor/tool_tier.go` |

## 1. Summary

A tool reaches the network today with nothing but its own good behaviour
between it and the rest of the world:
- the sensor admits a job's targets against its local policy before the task
  starts;
- after that, the tool process opens any connection it likes.

This RFC moves the scope check from "before the task" to **every packet the
task sends**:

1. **Per-task network confinement.** Every task runs in its own network
   namespace with no route out. Its only exit is a per-task relay to the
   sensor's **forwarder**, one implementation shared with RFC-034. The
   forwarder:
   - checks every destination against the job's admitted targets, the zone
     and the local policy;
   - pins DNS;
   - applies the rate limit;
   - records every destination.

   No tool, built-in or third-party, can bypass it, whatever code it runs.
2. **Invariants and overrides, as an explicit contract.** Once invariants are
   enforced outside the tool process, the SDK opens the tool-facing surface:
   - User-Agent, headers, TLS options for targets, timeouts, retries,
     resolvers;
   - extra arguments and list parameters for wrapped CLIs;
   - an operator layer of per-tool defaults.

   They are available the same way in Go, in the adapter protocol and in
   `tool.yaml`, logged as effective configuration and restrictable by
   tenant policy.
3. **Verified built-ins.** A tool's `builtin` origin is honoured only when the
   sensor release's signed list contains its descriptor digest. Since
   openctem#1475 the claim already counts only for the built-in tool names.
4. **A conformance kit that proves scope.** `openctem tool test --scope`
   reads the forwarder's record. A tool that contacts any address it was not
   given fails.

## 2. Problem (verified 2026-10-08, sdk-go `main` b1383c4)

| # | Finding | Evidence |
|---|---|---|
| P1 | No backend enforces a task's network class. `Status.NetworkEnforced` is never set | `executor.go` ("the process backend records it in the result; it does not enforce it") |
| P2 | Scope is checked once, at admission. After it: DNS can be rebound, redirects and discovered hosts leave scope at the packet level, and a compromised tool or template can exfiltrate | `core.LocalPolicy.AdmitCommandTargets`; `CheckDial` is used only by validation dials |
| P3 | `ctx.HTTP()` is an in-process allowlist, and it is too closed: no TLS options (cannot scan a self-signed target), `Proxy: nil` (ignores the scan proxy), no User-Agent, no custom transport. A real tool therefore builds its own client and bypasses it | `internal/toolrt/http.go` |
| P4 | Exec tools take only scalar `{{config.k}}` placeholders. A list param (`record_types`) cannot become flags, and an absent key becomes an empty argument. The capability params such a tool declares are silently ignored | `toolhost/exec.go` |
| P5 | The kit's `--scope` check listens on one random port of 127.0.0.2 that the tool is never told. A tool that fetched an external URL and probed 127.0.0.2:22/80/443/8080 passed | hands-on experiment, 2026-10-08 |
| P6 | A tool's `builtin` origin was a sensor claim honoured for any name | fixed by name in openctem#1475; digest binding here |

## 3. Goals and non-goals

**Goals:**
- An invariant holds whatever the tool's code does.
- Every target-facing knob is overridable by the tool author, the operator or
  the workflow, within ceilings.
- The same contract applies to Go, adapter-protocol and exec tools.
- Overrides are visible per run and restrictable per tenant.
- The kit proves the invariants.

**Non-goals:**
- Evading a target's defences: never switch egress because a target blocks
  (RFC-034 non-goal kept).
- Hiding the scanner's identity from the target owner (a tenant may force an
  honest User-Agent; §4.4).
- Raw-packet scanning: SYN, ICMP and UDP tools need the kubernetes backend
  with a NetworkPolicy, or stay refused in confined zones (RFC-034 O9).

## 4. Design

### 4.1 The contract: invariants, ceilings, free overrides

| Tier | Items | Who may change them | Enforced where |
|---|---|---|---|
| **Invariant** (never overridable) | the scope/authority check before any packet leaves (local policy ∩ platform gate ∩ job targets ∩ zone, exclusions applied); link-local, metadata and internal ranges unless the zone allows them; the SSRF guard toward the platform; the sandbox; credentials only through the broker; the sensor's identity and keys unreadable; tenant and sensor ids and provenance stamped by the runtime; result validation limits | nobody; local and platform policy can only narrow | forwarder + netns (network); executor (process, files); toolhost and ingest (results) |
| **Within ceilings** (may lower, never raise) | rate, concurrency, tier/intrusiveness, targets per task, run time, memory, zones | tool author (request), workflow step, operator | toolhost: `min(request, policy)`; platform grant tier ceiling |
| **Free** | User-Agent and request headers, timeouts, retries and backoff, concurrency within the task, DNS resolvers (answers still pinned by the forwarder), TLS options for targets (SNI, ALPN, minimum version, client certificate, skip verification), target proxy (inside the egress profile), output and parser choice, log fields, wordlist and template selection (RFC-061 slots), extra arguments to the wrapped program | tool author default < operator < workflow step < run | tool process, through the SDK |

Every value of the last two tiers that faces a target (User-Agent, header
names, rate, TLS skip-verify, proxy) is written to the task's effective
configuration line in the command log and to the result provenance. Tenant
policy may narrow it:
- force a User-Agent;
- forbid skip-verify;
- cap the rate;
- deny extra arguments.

The User-Agent and skip-verify narrowing is built in two layers:

- **Sensor-local policy** (schema v3 `http`). The network owner decides first.
- **Organization** (Settings > Security: `tool_http_user_agent`, `forbid_tool_insecure_tls`).
  - The platform puts it in every scan job as `http_policy` when the job is delivered, so a queued job gets the policy in force when it leaves.
  - The platform replaces any value a command's creator set.
  - The organization's User-Agent applies unless the local policy forces one.
  - Forbidding skip-verify refuses the tool even where the local policy allows it, but can never allow what the local policy forbids.
  - Turning the refusal off again is audited at high severity.

### 4.2 Per-task network confinement (process backend)

```
 task process (netns: lo only)             sensor (host netns)
 ┌───────────────────────────────┐         ┌──────────────────────────────────┐
 │ tool ──HTTP CONNECT/SOCKS5──▶ │         │ forwarder (one per task)         │
 │   relay 127.0.0.1:<p> ────────┼─unix───▶│  destination = admitted targets  │
 │ resolver 127.0.0.1:53 ────────┼─unix───▶│   ∩ zone ∩ local policy          │
 └───────────────────────────────┘ socket  │  pins DNS, rate limit, records   │
                                           │  upstream: direct | RFC-034 proxy│
                                           └──────────────────────────────────┘
```

1. **Namespaces.** The launcher (already the sensor binary, re-executed)
   unshares a user, network, mount and PID namespace before it applies
   Landlock and seccomp. The seccomp filter already refuses namespace
   creation to the tool afterwards.
   - In the new network namespace only `lo` exists: nothing routes out.
   - The PID namespace hides sibling tools' `/proc` (closing the residual of
     sdk-go#208).
   - The mount namespace binds a per-task `resolv.conf` naming
     `127.0.0.1`.
2. **Relay.** The launcher keeps one small process in the namespace. It
   listens on `127.0.0.1` for HTTP CONNECT and SOCKS5, and on UDP/TCP 53, and
   carries each connection and query over a **pathname unix socket** in the
   task directory to the sensor's per-task forwarder. Pathname sockets cross
   network namespaces; nothing else does. The tool gets
   `HTTP(S)_PROXY` / `ALL_PROXY` pointing at the relay.
3. **DNS.** The relay answers only for names the forwarder admits (job
   targets and their admitted subdomains) with the addresses pinned at
   admission. Anything else gets `NXDOMAIN`. This closes DNS rebinding and DNS
   exfiltration.
4. **Forwarder.** This is RFC-034's forwarder, run for **every** confined task,
   not only for proxied zones.
   - **Destination check:** every CONNECT or SOCKS request is checked against
     admitted targets ∩ zone ranges ∩ local policy, minus exclusions; plus
     RFC-056 web scope for HTTP through it; never metadata or link-local.
   - **Upstream:** direct, or the zone's egress profile (failover per
     RFC-034 §6.7).
   - **Rate:** a token bucket per task and per target host (closes RFC-055
     TC14).
   - **Record:** every destination with bytes and verdict goes to the
     task's provenance and the kit. A refused destination is a log line with
     the reason, never a silent drop.
5. **Availability.**
   - **Network enforced:** unprivileged user namespaces are allowed (most
     distributions; containers need the default seccomp profile to allow
     `unshare`, or the sensor runs with `CAP_SYS_ADMIN` dropped after setup).
     The backend reports `NetworkEnforced=true`.
   - **Not enforced:** where the kernel or container forbids it, the backend
     reports `NetworkEnforced=false` with the reason. `SENSOR_SANDBOX=required`
     then refuses to start, and `auto` runs as today with a warning in the
     config doctor.
   - **Kubernetes backend:** the same forwarder runs as the sensor Pod's
     sidecar service, and the task Pod's NetworkPolicy allows egress only to
     it.
   **Measured (2026-10-08, Linux 6.8):**

   | Environment | Unprivileged user + network namespace |
   |---|---|
   | Ubuntu 24.04 host (`kernel.apparmor_restrict_unprivileged_userns=1`) | refused (the `uid_map` write is denied) unless an AppArmor profile for the sensor binary grants `userns` |
   | Docker, default seccomp profile, non-root user | refused (`unshare` gets EPERM) |
   | Docker, a seccomp profile that allows `unshare`/`clone` with namespace flags, non-root user | works (only `lo` in the namespace) |
   | Container root mapping uid 0 | refused without `CAP_SETFCAP`; the sensor runs non-root, so it maps its own uid |

   Deployment therefore ships with:
   - a seccomp profile for the sensor container: the runtime default plus
     `unshare`/`clone` with user, network, mount and PID flags. It is
     referenced by the Compose file and the Helm chart (`Localhost` profile);
   - an AppArmor profile for host installs that grants `userns` to the sensor
     binary only.

   Platform (shared) sensors are deployed by the platform operator with
   both, and run `required`.

   Where neither is installed, Landlock ABI 4 (Linux 6.7+) can still limit
   TCP `connect` to the relay's port, and seccomp can refuse UDP sockets
   other than to the relay. That narrows egress to one port; it is not an
   invariant, so the backend still reports `NetworkEnforced=false`.
6. **Tools that ignore proxy variables.**
   - Every built-in tool honours them, or takes a proxy flag that the
     toolhost sets (RFC-034 §6.5 table).
   - A third-party tool that dials directly gets "connection refused"
     (no route), which is the safe failure.
   - A transparent mode (a userspace TCP stack in the namespace) is a later
     option, on evidence.

### 4.3 Verified built-ins

- The sensor release pipeline writes `builtin-tools.json`, listing
  `{name, descriptor_digest}` for every compiled-in tool. It is produced by
  `openctemio-sensor tools manifests` and signed with the release (cosign
  keyless, like the images).
- The platform keeps the lists of the releases it supports. A contract's
  `origin: builtin` is honoured only when
  `(sensor version, tool name, descriptor digest)` is in the list for that
  version.
- Otherwise the tool is `unverified` (T2), and the tool availability view
  says "descriptor differs from release vX". A locally modified built-in can
  therefore never pass as built-in.

### 4.4 The override surface

**`tool.yaml` (additive, `openctem.io/tool/v1`):**

```yaml
http:
  user_agent: "acme-scanner/1.2 (+https://acme.example/scanner)"
  headers: {X-Scan-Id: "{{task.id}}"}
  timeout: 30s
  retries: {max: 2, backoff: 1s}
  tls: {insecure_skip_verify: true, min_version: "1.2", alpn: [h2, http/1.1]}
  resolvers: []              # answers still pinned by the forwarder
run:
  extra_args: {allowed: ["-silent", "-retries"]}   # or {passthrough: true}
  argv: [dnsx, "{{config.record_types...|-%s}}", -l, "{{task.targets_file}}"]
```

- **Exec placeholders.** `{{config.k...|-%s}}` repeats a list as separate
  arguments. `{{flag:config.k:-x}}` emits `-x <v>` only when `k` is set. An
  absent scalar emits no argument. These close P4. Every substituted value
  keeps the existing flag-injection and dangerous-flag checks.
- **Adapter protocol.** `run.task.http` and `run.task.extra_args` carry the
  effective values, an additive member negotiated with the
  `features: ["http_overrides"]` entry. Python, Rust and shell tools read the
  same fields.
- **Go.**
  - `ctx.HTTP(opts ...tool.HTTPOption)` takes `WithUserAgent`,
    `WithHeaders`, `WithTLS`, `WithTimeout` and `WithTransport(rt)`.
  - A custom `RoundTripper` is wrapped **inside** the SDK guard (scope, web
    scope, redirects).
  - `ctx.Dialer()` and `ctx.Resolver()` return guarded equivalents for TCP
    tools.
  - Hooks `OnRequest`, `OnResponse`, `OnRecord` and `OnProgress`.
  - All Beta for one minor.

  These are ergonomics and defense in depth. The invariant is the namespace
  (§4.2).
- **Operator layer.** `tools.d/<tool>.yaml` in the sensor's configuration
  directory (a protected path) supplies per-tool defaults, for example a
  corporate User-Agent or resolvers.
- **Order and log.**
  - Order: SDK default < `tool.yaml` < operator < workflow step < run.
  - The effective configuration (secrets masked) is one log line per task
    and part of provenance.
- **Tenant policy.** `tool_overrides` in the scan policy:
  `force_user_agent`, `forbid_insecure_tls`, `max_rate`,
  `allow_extra_args`. The platform sends it with the job (signed with the
  job, RFC-040), and the toolhost applies it last.

### 4.5 Conformance

- `openctem tool test --scope` runs the task confined and reads the
  forwarder's record. Any destination outside the targets fails, with the
  destination named.
- Where confinement is unavailable (macOS, containers without user
  namespaces), the check says so and fails in `--sandbox required`.
- **Invariants suite:** a fixture tool tries each of the following, and
  each must be refused and recorded:
  - an external URL;
  - `169.254.169.254`;
  - an out-of-scope loopback address;
  - a direct dial with no proxy;
  - a DNS lookup of an unadmitted name;
  - a custom Go `RoundTripper` to an unadmitted host.
- **Overrides suite:**
  - User-Agent and headers reach the fixture server;
  - skip-verify works against a self-signed fixture;
  - a list param becomes repeated arguments;
  - tenant `force_user_agent` wins over the tool's.

### 4.6 Threat model

| Threat | Before | After |
|---|---|---|
| A tool reaches a host outside the job (bug, redirect, discovered host) | Possible | Refused at the forwarder, recorded |
| DNS rebinding after admission | Possible | Answers pinned at admission; unadmitted names NXDOMAIN |
| Exfiltration by a compromised tool or template (HTTP, DNS) | Possible | Only admitted destinations; DNS closed |
| Bypass by a custom transport or raw socket | Possible | No route in the namespace |
| Reading sibling tools' `/proc` (environ, cmdline) | Possible (same UID) | PID namespace |
| Sensor claims built-in trust for a modified tool | Possible | Digest-bound to the signed release list |
| An override weakens an invariant (skip-verify toward the platform, proxy elsewhere) | n/a | Overrides apply to target traffic only; the platform channel never goes through the tool; tenant policy can forbid each target-facing override |
| The forwarder is a new attack surface | — | Small and fuzzed (CONNECT, SOCKS5, DNS parsers); runs in the sensor with no credentials beyond the RFC-034 proxy secrets; per-task instance; bounded connections and bytes |

### 4.7 Acceptance tests

1. The 2026-10-08 experiment fails `openctem tool test --scope`
   with "connection to example.org:80 refused (not a target)": a tool that
   fetches `http://example.org` and probes 127.0.0.2:{22,80,443,8080}.
2. In `ModeRequired`, a task's direct `connect()` to a non-target gets
   `ENETUNREACH`, and `169.254.169.254` through the relay is refused.
3. DNS: a target resolves to its admitted address after the authoritative
   answer changes (rebinding test). An unadmitted name gets NXDOMAIN.
4. All built-in tools' golden tests pass confined: nuclei, httpx, katana,
   naabu (connect scan through SOCKS5), dnsx (through the relay's resolver),
   subfinder (vendor hosts), trivy, semgrep and codeql (registry or vendor
   hosts per descriptor).
5. Rate: a tool asking for 1000 req/s under a local cap of 50 is held at 50
   by the forwarder.
6. Overrides and invariants suites (§4.5) pass. A tenant policy
   forbidding skip-verify refuses a task requesting it with `invalid_input`.
7. Verified built-ins:
   - a sensor reporting `origin: builtin` with a digest not in its release
     list → unverified, T2;
   - the matching digest → builtin;
   - a cross-tenant contract → not visible.

## 5. Phased plan

| Phase | Deliverable | Repos |
|---|---|---|
| N1 | Forwarder core shared with RFC-034 (CONNECT, SOCKS5, DNS, destination check, record, rate), fuzzed | sdk-go |
| N2 | Launcher namespaces + relay; `NetworkEnforced`; config doctor checks; kit `--scope` on the record; invariants suite | sdk-go |
| N3 | Built-in tool wiring and golden runs confined; `SENSOR_SANDBOX=required` recommended for shared sensors | sensor |
| N4 | Override surface (tool.yaml `http`, exec list and optional placeholders, `extra_args`, protocol `run.task.http`, Go options, operator layer, effective config); tenant `tool_overrides` | sdk-go, sensor, api, web |
| N5 | Signed `builtin-tools.json` in releases; platform digest binding; availability view text | sensor, api |

## 6. Alternatives considered

| Option | Why not |
|---|---|
| seccomp user notification on `connect()`, checked by the sensor | The checked `sockaddr` lives in the tool's memory and can change between the check and the call (a time-of-check race), and `sendto`/`sendmsg` and DNS need the same treatment. Closing the race means the supervisor opens the socket itself, which is the forwarder with extra steps |
| `LD_PRELOAD` interception | Static binaries (every Go tool) ignore it |
| Firewall rules by UID or cgroup | Need root or `CAP_NET_ADMIN` on the host, and a UID per task |
| Container per task | The kubernetes/rootless backends remain the right answer where available. The process backend still needs a confinement of its own |
| Keep the in-process guard only | Every tool that needs one TLS option bypasses it (P3) |

## 7. Decisions (owner delegated 2026-10-08)

| # | Decision |
|---|---|
| N-D1 | Invariants are enforced out of process; in-process guards are ergonomics only |
| N-D2 | One forwarder implementation for RFC-034 and this RFC; every confined task uses it |
| N-D3 | `required` sandbox mode for platform (shared) sensors once N3 ships; tenants' own sensors default to `auto` |
| N-D4 | Built-in trust is bound to the signed release digest list (N5) |
| N-D5 | Overrides are open by default, visible, and narrowed by tenant policy, never by hard-coded SDK limits |
