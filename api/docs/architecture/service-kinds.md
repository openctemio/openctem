# Service kinds

What a network service speaks: every service asset carries a normalised
**kind** (its application protocol), the kind's **category**, and the
**source** the platform learned the kind from.

Status: **shipped** (taxonomy, classification on every write, backfill,
inventory facets, exposures for risky internet-facing kinds). **Planned:**
service detection (`detect.services@1`) on sensors, per-kind capability
applicability, a dashboard tile, kind-weighted attack-graph edges and version
matching on detected products.

Key files:

- `configs/asset-types.yaml`: `service_categories`, `kind_sources`,
  `service_kinds` and the attributes that take their values (`values_from`).
- `cmd/gen-asset-types/service_kinds.go`: validation and generation (Go, TS,
  the backfill's SQL tables with `-service-kinds-sql`).
- `pkg/domain/asset/servicekind.go`: `ClassifyService`,
  `ApplyServiceClassification`, `(*Asset).ClassifyService`.
- `internal/app/ingest/service_kind.go`: the source of a report's protocols.
- Migration `20261105123637_service_kind_backfill`.
- Web: `features/asset-types/lib/attribute-values.ts` (value labels).

## Keys

| Key | Meaning |
|---|---|
| `service_kind` | the application protocol from the closed registry list (`rdp`, `smb`, `http`, `redis`, `modbus`, ...) |
| `service_category` | the kind's category: web, remote_access, file_share, database, cache, search, mail, directory_auth, network_mgmt, messaging, container_orchestration, vpn, voip_media, industrial_ot, other |
| `kind_source` | how the kind is known; its confidence is fixed per source |
| `has_tls` | TLS is not a kind: `https` is `http` with TLS, `ldaps` is `ldap` with TLS |

All three kind keys are **derived**: they are reserved property keys, so a
report's properties never carry them, REST create and import refuse them, and a
patch may only echo the stored value. The registry marks the attributes
`derived`, so the asset forms do not offer them.

## Sources and precedence

| Source | Confidence | When |
|---|---|---|
| `fingerprint` | 95 | the report is bound to `detect.services` and names a protocol |
| `tls_alpn` | 85 | the report is bound to `check.tls` and names a protocol |
| `http_probe` | 80 | a web service (sub-type `http`), or a report bound to `probe.http` |
| `reported` | 60 | any other report, an import, a REST write |
| `port_guess` | 30 | no protocol: the port's well-known service for its transport |

The source of a write is the platform's own fact: the capability the output
binding bound the report to (from the command's tool). A report that is not
bound to a command (a push, an upload) is `reported`, whatever it claims.

A source never overwrites the kind of a higher source; an equal source does
(the service may have changed). So a weekly port scan never downgrades a
detected kind, and a new detection replaces an old one.

Reading a protocol name: lower case, `_` and spaces read as `-`; an `ssl/` or
`tls/` prefix means TLS; a trailing `?` marks the producer's own guess (it
counts as a port guess); a transport (`tcp`, `udp`, `sctp`), `unknown`,
`general` or `tcpwrapped` is no protocol. A measured name that is not in the
table gives **no** kind rather than a port guess, and stays in `protocol`.

## Port guesses

The port table holds only ports with one well-known service. A port guess is
always shown as a guess (a "Guess" label next to the kind) and never on its
own raises an exposure above the port's own `port_open`, creates a finding or
decides an active check. It only says which open ports are worth a detection
run.

## Backfill

The migration classifies every stored service from its own properties with
this release's tables (same rules as `ClassifyService`): a known name gives
its kind (`http_probe` on a web service probed by httpx, otherwise
`reported`), a web service without a name speaks `http`, anything else gets a
port guess. Open ports whose `protocol` held the transport have it moved to
`transport`. Rows with a kind are left alone. Later table changes reach rows on
their next scan.

## Inventory

`service_kind`, `service_category` and `kind_source` are the first facets of
the Services, HTTP services and Open ports views ("all remote-access
services" is the category facet). Values show their registry labels in the
viewer's language; the kind list offers only the kinds the tenant has.

## Risky services

An open port raises a `risky_service_exposed` exposure (display category
`exposed_ports`, `internal/app/exposurebridge/risky_service.go`) when:

- its kind has a `risk` in the registry (RDP, VNC, Telnet, SMB, NFS, every
  database, cache and search engine, Docker, Kubernetes, kubelet and etcd
  APIs, every industrial protocol, ...; SSH, web, mail and VPN have none);
- the kind was measured: any source but `port_guess`;
- the service is internet-facing: its exposure is public or it is marked
  internet-accessible, or its address (host of its name, `host`,
  `ip_addresses`) is public; an exposure of private, restricted or isolated
  decides against;
- its state is not closed or filtered.

Severity is the kind's `risk`; `risk_anonymous` when a probe saw the service
answer without credentials (`has_anonymous_access`), as its own exposure, so
a severity someone reviewed never changes under them. Dedupe keys: port,
transport and kind. When the kind changes, stops being risky, becomes a guess
again or the anonymous state flips, the port's other risky exposures are
resolved automatically; closing the port resolves them with `port_open`.

`port_open` keeps its identity: its key is the transport (an older port scan
filed it under `protocol`, which now holds the application protocol). It
names a measured kind (`service_label`) and a guess only as a guess
(`service_guess`: "Port 6379 is open to the internet (probably Redis)"); a
port number alone no longer names a service in a summary.

## Threat model

- *Producer raises its own confidence.* The source comes from the receiver's
  binding, never the report; the kind keys are reserved on every write path.
- *Hostile banner or protocol name.* A kind comes only from the closed table
  (a name longer than 64 bytes is not looked up), so no value can invent a kind
  or category; banners are stored as data, rendered as text and never logged.
- *Cross-tenant effect.* Classification is a pure function of one asset's own
  properties; the backfill is row-local (tests: `TestClassifyService_*`,
  `TestMigrationServiceKindBackfill`).
- *A guess drives action.* Guesses are labelled and excluded from exposures,
  findings and active checks.
- *Exposure spam on reclassification.* Stable keys; a changed kind resolves
  the old exposure; the port_open key never moves (`TestPortOpen_*`,
  `TestRiskyService_*`, cross-tenant negative included).
