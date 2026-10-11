# RFC-082: Network seeds (AS numbers, organizations, CIDR)

| | |
|---|---|
| Status | Implemented (2026-10-11) |
| Scope | api (`pkg/domain/easmseed`, `internal/app/easm/network_seeds.go`, `ripestat.go`, review-queue address rows, `/api/v1/easm/network-seeds`, weekly refresh controller, one migration), web (Scoping › Scope › Networks) |
| Architecture | [easm.md §4k](../architecture/easm.md#4k-network-seeds-built) |
| Related | RFC-036 (EASM, phase P2 seeds and attribution), RFC-054 (scope model: only scope entries authorize probes; guardrails §8), research/106 §9 item 3 |

## 1. Summary

Discovery starts from what an organization asserts about itself. Domains are
covered: a permanent `*.example.com` scope entry with discovery on is the
root-domain seed (RFC-054). Address space was not: an organization could not
say "AS64500 is ours" or "we are Example Corp" and see which ranges follow.

- **AS number seeds** are expanded from public routing data into the prefixes
  the AS announces. Each prefix is checked against the platform guardrails
  (deny list, public CIDR caps) and offered as a CIDR scope entry, added
  through the normal scope flow (approvals, step-up, signer, audit).
- **Organization seeds** are expanded into the AS numbers registered to the
  name; a person adds the right ones as AS seeds.
- **CIDR seeds** are CIDR scope entries, as today; nothing new is stored.
- In the review queue, an address in a seeded AS, a seeded AS's announced
  prefix, or an AS whose organization names a seeded organization gets the
  range around it offered as a fix, like an organization-name match does.

A seed **never authorizes a probe** and never widens scope by itself.

## 2. Decisions

| # | Decision | Why |
|---|---|---|
| D1 | Data source: RIPEstat (`announced-prefixes`, `as-overview`, `searchcomplete`), free, no key, global routing data | Decision O1 (free sources by default); one fixed host |
| D2 | Fetched from the API through the SSRF-guarded client (`httpsec.SafeHTTPClient`), one request per second per process, 4 MiB responses, strict decoding | Same pattern as the CT monitor; no sensor needed for public metadata |
| D3 | Expansion results are suggestions only; scope entries come from the scope flow | RFC-054: only scope entries authorize probes; approvals and guardrails stay the gate |
| D4 | A cloud or CDN AS (shared provider list) offers no prefixes; organization search drops shared ASes and keeps only ASes whose registration names the organization | Those networks serve other organizations |
| D5 | No platform-side reverse-DNS sweep of CIDR entries | Sweeping netblocks is active-ish volume work; it belongs in the sensor pipeline (dnsx PTR, RFC-036 P3) |
| D6 | No new scope target type for ASN | An AS changes owners and leases; authorizing by AS would authorize addresses nobody reviewed |

Not built: Team Cymru or WHOIS lookups, per-tenant source keys, automatic
attribution confirmation from a seed (the review queue stays a person's
decision), favicon/analytics-id seeds.

## 3. Design

- Table `easm_network_seeds` (tenant, kind `asn`|`org_name`, value, label,
  holder, prefixes ≤ 1000, suggestions ≤ 50, last expansion, last error);
  unique per tenant, kind and value (case-insensitive); at most 50 seeds per
  tenant, enforced in the insert statement.
- Values: AS numbers normalized to `AS<n>`; 0, 23456, 65535, documentation
  (64496–64511, 65536–65551) and private (64512–65534, ≥ 4200000000) numbers
  refused. Organization names 3–200 characters, no control characters.
- `POST` starts the first expansion in the background; `POST
  /{id}/expand` refreshes at most once per 15 minutes per seed (429); the
  `easm-network-seed-refresh` controller (every 6 h, module-gated) refreshes
  seeds older than 7 days. A failed lookup keeps the previous data and stores
  a generic error (no response content).
- Routes (module `attack_surface`, scope permissions like the verified
  domains): `GET /api/v1/easm/network-seeds` (`scope:read`), `POST`
  (`scope:write`), `DELETE /{id}` (`scope:delete`), `POST /{id}/expand`
  (`scope:write`). Add, remove and refresh are audited
  (`easm_network_seed.*`).
- The list returns, per AS seed, `prefix_suggestions` (prefix, allowed,
  guardrail refusal code) and `shared`; per organization seed the matching AS
  numbers.
- Review queue: `ReviewNetwork.seeded`; with it the /24 or /48 around the
  address is offered (approvers only), never for shared space.
- Web: Scoping › Scope › **Networks** tab: add a seed, see the holder and
  prefixes, add a prefix as a scope entry (the scope entry dialog, prefilled),
  add an AS found for an organization; en, vi.

## 4. Threat model

| Asset / actor | Abuse case | Control |
|---|---|---|
| Third parties | A tenant seeds someone else's AS to scan their ranges | Seeds authorize nothing; prefixes go through the scope flow, guardrails (deny list, CIDR caps) and, for platform sensors, domain/ownership proof; shared providers offer nothing |
| Another organization | Read or change seeds across tenants | Tenant from the token in every query; cross-tenant DB tests (get, delete, claim) |
| RIPEstat / network path | Hostile or huge response, SSRF via redirect | SSRF-guarded client, fixed host, size cap, strict JSON, every prefix parsed and canonicalized, every AS normalized, text cleaned and capped |
| Data disclosure | AS numbers and organization names sent to RIPEstat | Documented in the UI; public data about the organization; nothing else is sent |
| Abuse of the source | Many refreshes | 15-minute cooldown per seed, 1 request/s per process, 50 seeds per tenant, weekly refresh |

## 5. Rollout

Migration `easm_network_seeds` (new table). Nothing changes until a tenant
adds a seed.

## 6. Tests

`pkg/domain/easmseed` (AS and name validation); `easm.TestNetworkSeedService`
(guardrails on prefixes, shared AS, organization filtering, generic error,
cooldown, unknown seed); `TestSeededNetwork`; `TestRIPEstatClient` (decoding,
canonical prefixes, cleaning) and `TestRIPEstatClientIsGuarded` (the
production client refuses loopback); `TestExplainAddresses_SeededNetworkOffersTheRange`;
`postgres.TestEASMNetworkSeedRepository` (duplicates, cap, cooldown claim,
failed refresh keeps data, cross-tenant negatives); handler test; web panel
test.
