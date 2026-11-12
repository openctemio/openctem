# RFC-151: Large range targets

| | |
|---|---|
| Status | Implemented (2026-11-06) |
| Scope | api (target validator, scan create and run, dispatch gate, scope settings), web (New scan Targets step, Scope policy) |
| Architecture | [scan-targets.md](../architecture/scan-targets.md), [active-probe-gate.md](../architecture/active-probe-gate.md) |
| Related | RFC-088 (scope-aware target allocation, live hosts first), RFC-023 (scan zones), RFC-054 (scope model) |

## 1. Problem

A scan target held at most 2^16 addresses (an IPv4 /16, an IPv6 /112). An
organization that scans its whole internal network (`10.0.0.0/8`,
`172.16.0.0/12`) had to type hundreds of /16 ranges, and New scan said only
"1 typed line is not a target". The platform already cuts ranges at
dispatch and spreads the pieces over sensors, so the bound was a limit of
the validator, not of the dispatch.

## 2. Decisions

1. **Bound.** One target may name up to 2^24 addresses: an IPv4 /8, an IPv6
   /104. The bound is an address count, the same for both families, because
   the cost of a host discovery sweep is the number of addresses probed. An
   IPv6 network wider than a /104 (a /64 holds 2^64 addresses) cannot be
   swept at all; its hosts come from the inventory and passive sources, so
   the bound stays at the same count instead of following prefix habits.
2. **Per-organization limit, opt-in.** Scope policy setting
   `max_range_prefix` (IPv4 prefix length 8 to 24; IPv6 gets the same address
   count). The default for every organization, existing ones included, is
   16: a range wider than a /16 is refused until the organization opts in.
   It is changed through `PUT /scope/settings` (scope approval permission and
   step-up). Raising it (a lower prefix) widens what one scan may sweep: the
   change is audited at high severity with the widening named in the audit
   message (`range_widened`), and every administrator gets a notice that
   names the old and new limit. Lowering it needs nothing more. The limit is
   read at scan create, at the scope check of New scan, at edit and at every
   run, and New scan reads the organization's limit to explain a refusal
   before create. Lowering it refuses wider ranges in saved scans at their
   next run.
3. **Large range = live hosts first.** A range wider than a /16 is scanned
   only with `cidr_mode: liveness`: the host discovery step sweeps it and
   only the hosts it finds reach the port and vulnerability stages. Saving
   such a scan with `sweep` or `inventory` is refused
   (`LARGE_RANGE_NEEDS_LIVENESS`). Only a scan that finds hosts first may
   hold one: a workflow with a host discovery step, or a single-scanner scan
   whose scanner is the host discovery tool. A workflow without that step,
   and a single port or vulnerability scanner (it would probe every address
   it is handed), are refused (`LIVENESS_NEEDS_HOST_DISCOVERY`); an unnamed
   mode becomes liveness. The mode is settled again on every edit of the
   targets, target options, workflow or scanner. The run holds a scan to a
   /16 unless it is in liveness mode and still finds hosts first (its
   workflow steps are read again at the run).
4. **Expansion at dispatch only.** A scan stores the range as typed. When a
   run resolves its targets, the dispatch gate cuts each large range into
   prefixes no wider than a /16 (IPv6 /112), after removing:
   - the addresses no scope entry of an address kind (address, range, CIDR)
     of this organization covers, counted as `out_of_scope_addresses`;
   - the active exclusions of an address kind and the built-in deny list
     (as for every range, RFC-088).
   Nothing is listed per address: a /8 is 256 prefixes, one run target each.
   Every range gets this bound and cut, asset group members included: a
   network asset wider than a /16 that also matches by its name is refused
   or cut like a typed range, and its pieces keep its names, so an exclusion
   of the asset's name still removes every piece.
   Each prefix then passes every check of the gate on its own (ownership,
   act scope, tier, zones). The cut only removes addresses; it never
   authorizes one.
5. **Whole range in scope at create.** The scope check and scan create judge
   the typed range as one target: a scope entry must hold all of it. The run
   cut above keeps a scan safe when the scope shrinks later.
6. **Routing.** Each prefix routes like any address target: to the scan zone
   whose ranges hold it, and to that zone's sensors. An internal range is
   accepted at create only when one zone holds the whole range.
7. **Limits unchanged.** Every prefix is an ordinary job. The sensor's own
   rate and concurrency limits, the per-run job bound (1,000) and the piece
   budget (4,096 prefixes per dispatch) apply as before; past them the run is
   refused with `TOO_MANY_JOBS` or `RANGE_TOO_FRAGMENTED`, never truncated.
8. **Other paths keep the /16 bound.** Commands that hand targets to a
   sensor as typed (a direct command, a run started with context targets, a
   claim-time re-check) never take a range wider than a /16, so a large range
   can reach a sensor only as /16 prefixes.
9. **Confirmation, enforced by the API.** Creating a scan, editing its
   targets or importing a configuration whose direct targets name a range
   wider than a /16 needs `confirm_large_range: true` in the request
   (`?confirm_large_range=true` on import); without it the API refuses with
   `LARGE_RANGE_UNCONFIRMED`, whose message and details name the ranges, their
   address count and the most /16 chunks they become. New scan sends it only
   after its Targets step showed the address count, the number of /16 chunks
   and a rough host discovery duration on one sensor (at a planning rate of
   1,000 addresses a second, shown with the estimate) and the person
   confirmed; a change of ranges asks again. Other API callers must send it
   explicitly; no MCP tool creates scans.
10. **One validator contract.** The bound and its refusal text are shared by
    the API validator and the web format check through
    `api/pkg/validator/testdata/cidr_targets.json`, read by both test suites.
    The file also states which ranges are internal (scanned only inside a
    scan zone): a range is internal when it overlaps a private, link-local or
    loopback block at all, so `172.0.0.0/8` (holding `172.16.0.0/12`) needs a
    zone like `10.0.0.0/8` does.
    A range too wide says how many addresses it has and the most one target
    holds, and offers a one-click split when it fits in at most 256 ranges of
    the widest accepted size.

## 3. Measured

`BenchmarkLargeRangeSplit` (api/internal/app/scan): a /8 cut around 100
scattered single-address exclusions is 1,756 prefixes in about 21 ms and
1.2 MB per dispatch (no per-address work). Without exclusions a /8 is 256
prefixes. With the 10 targets per job New scan sets, 1,756 prefixes are 176
jobs; with one target per job they exceed the per-run job bound and the run
is refused with `TOO_MANY_JOBS`. About 300 scattered exclusions inside one
/8 exceed the piece budget (`RANGE_TOO_FRAGMENTED`).

## 4. Threat model

- **Abuse of a wide sweep** (a member sweeps a /8 the organization does not
  want swept): bounded by the organization's `max_range_prefix` (a /16
  unless an approver opted in, with step-up, audit and notice), the scope
  entries (only covered addresses are sent), the confirmation the API
  requires, live hosts first (only a scan that finds hosts first may hold a
  large range, so no port or vulnerability scanner is handed the whole
  range), scan approval governance where it is on, and the sensor's rate
  limits.
- **Bypass through other target sources**: asset group members are bounded
  and cut like typed ranges; a range that only looks public by its first
  address (`172.0.0.0/8`) is internal and needs a scan zone.
- **Cross-tenant authorization**: the in-scope address set and the
  exclusions are loaded for the scan's tenant only; another tenant's entries
  never authorize or cut a range (test `TestLargeRange_CrossTenantScope`).
- **Fail closed**: a failed scope or exclusion lookup dispatches nothing; a
  gate without an address source refuses a large range instead of sending it
  whole; the default bound of every other path stays a /16.
- **Resource exhaustion of the platform**: no per-address rows or lists;
  piece and job bounds refuse a run that would fan out too far.

## 5. Not covered

- A range spanning several scan zones is accepted only when one zone holds
  it all; cutting prefixes at zone boundaries is a later change.
- The duration estimate uses a fixed planning rate, not the zone's sensors
  and their limits.
