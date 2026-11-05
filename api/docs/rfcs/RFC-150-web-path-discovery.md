# RFC-150: Web path discovery

| | |
|---|---|
| Status | Partially implemented (2026-11-05): platform planning, derived list, strict job scope, budgets, program rules, coverage reasons and the workflow step; the check for guessed files exists in the sensor, its wiring is planned |
| Scope | api (`pkg/domain/webendpoint`, `internal/app/contentpin`, `internal/app/scope`, `internal/app/coverage`, `internal/app/scanrun`, `internal/app/command`, stage catalog, migrations), contract (`enumerate.web_paths@1`, `webpath`), sdk-go (forwarder request cap), sensor (`webguess`) |
| Architecture | [web-discovery.md](../architecture/web-discovery.md) |
| Related | RFC-056 (web surface store; §9 guessed endpoints and evidence), RFC-093 (asset coverage ledger), RFC-061 (job content), RFC-065 (bug bounty programs), RFC-074 (coverage gaps) |

## 1. Problem

Paths a site never links (backups, old API versions, the same application on
another host) are among the most valuable exposures and are invisible to a
crawl. Finding them means requesting paths nothing points at, which is volume
toward the target. The platform must decide which paths, how many, where and
when, and the sensor must not be able to widen any of it.

## 2. Decisions

| # | Decision |
|---|---|
| D1 | Path discovery is its own capability, `enumerate.web_paths@1`, tier T1, GET and HEAD only. Parameter discovery is a separate T2 capability (`enumerate.web_params@1`, reserved). |
| D2 | The platform plans; the tool never extends its list, never recurses and never follows redirects. |
| D3 | Steady discovery uses a **derived list** built from the organization's own inventory: backup copies of observed files, older and next API versions of observed versioned paths, paths at least two of the organization's other origins serve, and declared API paths never observed. Pack lists (S/M/L) are later and opt-in. |
| D4 | Derived discovery is on by default at Standard depth, with an organization switch (scope settings `path_discovery`), audited. |
| D5 | The job's web scope is strict: methods GET and HEAD, every path exclusion on the target hosts whose testing mode is not `allowed` is denied (`read_only` included), and a per-host request cap the sensor's forwarder enforces (`max_requests_per_host`). Exclusions are matched with the sensor's reading of paths (contract `webpath`) when the list is built. |
| D6 | Budgets: 300 requests per origin, at most one run per origin per 30 days unless its inventory changed; 50,000 requests per organization per day. Origins that do not fit are deferred, never marked covered. |
| D7 | Planned origins: live web services in scope by an active scope entry that names their host (inherited standing does not count); an address origin only with an address entry naming it, and labelled `shared_edge_address` (not refused as out of scope) on a shared edge network; an origin whose last probe an edge protection challenged or blocked is not planned. |
| D8 | A bug bounty program that forbids `bruteforce` or `automated_scanning` gets no enumeration job (any `enumerate.*` capability or brute force), with the reason, on every dispatch path. |
| D9 | The platform sets the stored source `guess` from the bound capability and requires response evidence (RFC-056 §9). A guessed row is an observation; a finding comes only from a platform-planned verification. |
| D10 | Per-origin outcomes are coverage gap reasons on the run: `catch_all`, `auth_wall`, `edge_protected`, `throttled`, `blocked`, `unstable_baseline`, `budget`, `hostile_response`, `protocol`, `scope_filtered`, `no_candidates` (no request was sent; the ledger claim is released). The ledger never marks an origin covered on `edge_protected`, `throttled` or `budget`. |

## 3. Design

### 3.1 Planning

Path discovery is a coverage capability of web services (RFC-093):
`enumerate.web_paths` every 30 days on `http_service` assets that satisfy
`origin_scope_entry`, `inventory_changed` and `edge_clear`. Before a batch
the coverage planner reads the organization's switch (off: the pairs pause
as `switched_off`), the daily request budget (the batch holds what the budget
left allows at the per-origin cap; the rest pauses as `budget`, deferred), and
per-target refusals (`program_forbids_enumeration`, `program_rules_conflict`,
`shared_edge_address`: blocked with the reason, rechecked later). The run is
standard depth with `lists: [derived]` and the per-origin cap.

The system recon workflows (Standard recon, Web, Deep recon) carry an
optional `paths` step at Standard depth on the probed web services. It goes
through the same gate as the planner (§3.5): skipped while the switch is off,
and at dispatch it keeps only the origins the gate lets through.

### 3.5 One gate for every caller

Three callers start path discovery: the coverage planner, a workflow's `paths`
step and a scan someone starts. They share one policy
(`coverage.PathDiscoveryPolicy`): the organization's switch, the daily request
budget, an active scope entry naming the origin's host, the shared edge and
program refusals, an edge that did not challenge the last probe, new inventory
since the last run, and the per-origin last-run record. That record is the
ledger `web_path_discovery_runs` (one row per origin: when it was last
dispatched, the request cap granted, the run). The planner and the workflow
step check it before they dispatch; the claim itself happens in the web job
guard every command passes before it is stored, under a per-organization lock,
so the 300 requests per origin per 30 days hold across scans and the planner,
and the daily budget is the sum of the caps granted. A retry of a task is a
new dispatch and is refused the same way. A job also requires `net.confined@1`.

The cap a job carries is the platform's: a request above the per-origin budget
is signed at the budget. The origins of one run on the same host name (other
ports, other schemes) share that host's budget across the run's tasks: each
claim is granted at most what the run's other claims on the host left.

### 3.2 Job content

At claim the content planner builds the derived list of the job's origins
from that organization's rows only, drops templated, destructive
(`webpath.Destructive`) and excluded paths, ranks the four sources in turn,
truncates to the inline cap (256 KiB gzip) and carries it inline in the
signed job. No pack is pinned for a derived-only job.

### 3.3 Job scope

The web job guard gives every path discovery job (capability
`enumerate.web_paths` or tool `webguess`) the strict scope of D5, replacing
anything the creator wrote. The sensor's forwarder counts requests per host
and refuses past the cap.

### 3.4 Outcomes

The sensor reports per-origin reasons in the task's `coverage_gaps`.
Settlement maps `edge_protected` to an edge challenge, `throttled` to rate
limiting and `budget` to unfinished (not covered); `catch_all`, `auth_wall`,
`unstable_baseline` and `scope_filtered` leave the origin covered with the
reason on the run.

## 4. Threat model

| Threat | Control |
|---|---|
| Discovery of a third party's site | coverage only on origins an active scope entry names; the dispatch gate at T1; ingest admits endpoints only under the command's targets |
| Exclusion bypass (case, encoding, dot segments, parameters) | strict scope (read_only denied); list filtered with `webpath` (the sensor's reading); tool pre-filter and forwarder |
| Destructive requests | methods GET and HEAD in the signed scope; destructive paths never listed |
| Volume against the organization's applications | per-host cap signed and enforced by the forwarder; one run per origin per 30 days; daily budget; edge-challenged origins skipped |
| Cross-tenant leakage through lists | the derived list reads only the job's organization's rows; inline, never stored |
| Program rules bypass | enumeration refused at trigger, in coverage planning and at claim when a covering program forbids brute force or automated scanning |
| A sensor faking discoveries | source set from the binding, evidence required (RFC-056 §9) |

## 5. Verification of guessed backup, archive and dump files

The sensor carries the nuclei template `openctem-backup-file-signature` in its
own compiled-in, per-run signed set (one GET of the exact URL, a match only on
zip, gzip, tar or SQL dump bytes in a non-HTML 200), so no platform template
delivery is needed. The web verification planner treats a guessed endpoint
(source `guess`) with an `ext:backup`, `ext:archive` or `ext:dbdump` label as a
candidate without a catalog entry and asks for that template by id in
`scanner_config.template_ids`, with the check's tag `openctem` in `tags` as a safeguard: a sensor that predates the setting ignores the id, and with that tag it loads no template instead of running its default set (deploy the sensor first all the same). The sensor's nuclei reads `template_ids` as the
selection of its own checks: only ids of the compiled-in set are accepted (any
other id refuses the scan), the run loads only the run-signed copies of those
templates with `-id`, signatures stay required, and the sensor's tag and
severity filters do not apply. The scan is a web-scoped nuclei job, so it
requires `net.confined@1` and the strict scope like any other. A finding comes
only from the template's hit in the normal ingest.

## 6. Not built yet

- Verifying guessed source and config files (the backup, archive and dump
  classes are verified, see below).
- Pack lists, platform-planned recursion, parameter discovery, authenticated
  discovery (target credentials through the sealed task secrets), the
  per-variant ledger.
