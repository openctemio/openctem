# RFC-036 Appendix: use cases, edge cases and threat model

> Part of [RFC-036](RFC-036-easm.md). A living document: every EASM pull
> request updates the rows it implements, and a row is only marked **tested**
> when the named test exists on `develop`. Rows marked *planned* describe the
> acceptance test the implementing PR must add.

The quality bar (2026-10-02): cover the realistic use cases and edge
cases, and give every security control of the EASM feature its own test.
EASM here means **authorized, in-scope monitoring of the tenant's own
internet-facing assets**. Nothing in this appendix describes probing anyone
else's infrastructure.

Test locations: `internal/app/certmonitor` (unit, fake HTTP sources),
`internal/infra/postgres/*_db_test.go` (real schema, `DATABASE_URL`), and the
scratch-stack e2e described under each phase (real API binary, scratch
Postgres/Redis, fake data sources on a private address, never production, never a
real third-party target).

## 1. Use cases

| # | Use case | Phase | Acceptance test | Status |
|---|---|---|---|---|
| U1 | A tenant with many domains gets **every** domain checked against CT, not just the first 50 | P0 | `TestMonitorTenant_RotatesThroughAllDomains` (120 domains, cap 50, all queried within 3 runs); scratch e2e (121 domains) | tested |
| U2 | Verified domains and domain scope targets are monitored even when no domain asset exists for them | P0 | `TestMonitorTenant_QueriesVerifiedAndScopeDomains` | tested |
| U3 | crt.sh is overloaded (502/503/timeout): the sweep retries, then uses Cert Spotter, and the tenant still gets results | P0 | `TestMonitorTenant_RetriesCRTSHThenSucceeds`, `TestMonitorTenant_FallsBackToCertSpotter`; scratch e2e (`flaky*` domain served by Cert Spotter) | tested |
| U4 | A certificate about to expire, or one that just expired with no replacement, raises an exposure | P0 | `TestCollectDiscoveries_ExpiryUsesNewestCert`, `TestCollectDiscoveries_ExpiredEmitsEvent` | tested |
| U5 | A subdomain first seen in CT becomes an inventory asset with its provenance and an attribution state (auto-confirmed only under a verified domain, otherwise awaiting review) | P0/P1 | `TestPromote_StatesByRootOrigin`, `TestEvaluate`; scratch e2e `promote_e2e.sh` (verified root → confirmed 99, listed domain → needs_review 85, `discovery_source=cert_transparency`) | tested |
| U5a | A person confirms, rejects, or marks an asset as a dependency / monitor only; automation never undoes it; the decision is audited | P0/P1 | `TestAssetAttributionHandler_Decide`, `TestMerge`, `TestAttributionRepository`; scratch e2e (confirm → next scan includes it, audit row, re-sweep keeps it) | tested |
| U5b | Anyone with asset read access sees why an asset is believed to be the organization's (`GET /assets/{id}/attribution`) | P0/P1 | `TestAssetAttributionHandler`; scratch e2e | tested |
| U6 | Recon jobs (subfinder, dnsx, httpx, naabu, katana) run only on sensors that actually ship the tool | P0 | *planned* (sensor image + dispatch PRs) | planned |
| U7 | Attack-surface cards show real counts or say there is no data, never a healthy-looking zero | P0 | *planned* (UI honesty PR) | planned |
| U8 | A CNAME pointing at an unclaimed cloud resource is flagged (dangling DNS / takeover candidate); a CNAME or delegation on an unregistered domain is high; the exposure resolves itself when the record is fixed and reopens if it breaks again | P1 | `TestCheckDangling`, `TestMonitorTenant_Lifecycle`, `TestEASMDNSRepository`; scratch e2e `dns_e2e.sh` (fake resolver: Azure takeover candidate → medium, unregistered target → high, dangling NS → high; fixed → resolved with history; broken again → same exposure reopened). Sensor confirmation → high is *planned* (nuclei `takeover`, T1) | tested (DNS part) |
| U9 | Weak email posture (no SPF, `+all`/`?all`, too many SPF lookups, DMARC missing / `p=none` / test mode / no `rua`, MTA-STS/TLS-RPT missing) on a tenant domain is flagged; correct domains are not | P1 | `TestCheckEmail` (golden fixtures incl. a correct mail domain and a correct parked domain), `TestMonitorEmail_FlagsWeakAndResolvesFixed`; scratch e2e. DKIM is *not* checked (no selector brute force) | tested |
| U9a | The daily light checks of O9 run for every tenant with the attack-surface module once enabled (`EASM_DNS_CHECKS_ENABLED`, off by default until the scans P1 work lands) | P1 | `TestEASMDNSController_Reconcile`; scratch e2e | tested |
| U10 | Every discovered asset says how and why it is attributed to the tenant (seed, technique, evidence, confidence) | P1 | *planned* | planned |
| U11 | The EASM overview shows the surface, what is new since the last cycle and the top risks, with numbers equal to the list counts | P1 | API: `TestEASMSummaryRepository`, `TestSummary_Build`; scratch e2e (summary subdomain/domain/exposure counts equal `GET /assets?types=` and `GET /exposures` totals). Web page: *planned* | API tested |

## 2. Edge cases

| # | Case | Handling | Test |
|---|---|---|---|
| E-1 | Tenant has more domains than the per-run cap | Rotation cursor: never-succeeded first, then oldest success, then oldest attempt; cap `CERT_MONITOR_MAX_DOMAINS_PER_RUN` (50) | `TestMonitorTenant_RotatesThroughAllDomains` |
| E-2 | API restarts several times a day (hot reload, deploys) | A domain queried successfully within 5/6 of the sweep interval is not due; restarts do not re-query | `TestMonitorTenant_RestartDoesNotRequery` |
| E-3 | Two API replicas run the controller at the same time | Per-tenant session advisory lock on a dedicated connection; the second replica skips the tenant | `TestMonitorTenant_SkipsWhenTenantLocked`, `TestCTMonitorStateRepository_TenantLock` |
| E-4 | crt.sh answers 502/503/429 or times out | Up to 3 attempts, exponential back-off with jitter (2 s → 30 s cap), `Retry-After` honored up to 60 s; response-header timeout 50 s (the shared client's 15 s was below crt.sh's normal latency) | `TestMonitorTenant_RetriesCRTSHThenSucceeds`, `TestRetryDelay` |
| E-5 | crt.sh answers 4xx other than 408/429, or a non-JSON body | Not retried; goes to the fallback | `TestMonitorTenant_NotFoundIsNotRetried` |
| E-6 | Both sources fail for a domain | Recorded in `ct_monitor_state`; back-off 12 h, 24 h, 48 h … 7 days, so a permanently failing domain never takes a slot every run; recovery resets it | `TestMonitorTenant_BothSourcesFail_BacksOffAndSkips`, `TestFailureBackoff` |
| E-7 | Cert Spotter free tier exhausted (429) | The rest of that sweep stops asking Cert Spotter | `TestMonitorTenant_BothSourcesFail_BacksOffAndSkips` |
| E-8 | Cert Spotter only lists unexpired certificates | A domain served by the fallback never raises `certificate_expired` from missing history (documented, by construction) | `TestMonitorTenant_FallsBackToCertSpotter` |
| E-9 | A child domain and its parent are both watched (`api.example.com` and `example.com`) | Only the parent is queried (its wildcard query covers the child); a **verified** child under an unverified parent stays its own root so its names keep the verified origin | `TestMergeRoots` |
| E-10 | Names that cannot have public certificates (`.local`, `.internal`, `.test`, bare suffixes like `co.uk`) | Dropped before querying (ICANN public-suffix check) | `TestMergeRoots`, `TestMonitorTenant_QueriesVerifiedAndScopeDomains` |
| E-11 | Wildcard patterns in scope targets (`*.example.com`) | Normalised to the base name | `TestMonitorTenant_QueriesVerifiedAndScopeDomains` |
| E-12 | Pending / failed domain verification | Not a monitored root (only `verified` rows) | `TestMonitorTenant_QueriesVerifiedAndScopeDomains` |
| E-13 | Years of historical certificates for one host | Expiry uses the newest `not_after` per host; `certificate_expired` only if the newest lapsed within 30 days | `TestCollectDiscoveries_ExpiryUsesNewestCert` |
| E-14 | A domain with thousands of CT names (CDN, wildcard) | At most 500 `subdomain_discovered` per domain per run; body capped at 48 MiB; Cert Spotter at 10 pages | existing `collectDiscoveries` cap; *planned*: truncated-body test |
| E-15 | One tenant's sweep takes very long (many failing domains) | Per-tenant time budget (30 min); unreached domains are not marked and lead the next run | `TestMonitorTenant_SweepBudget` |
| E-16 | Same discovery on every run | Exposure fingerprint dedupe (re-sighting, not a new row) | `TestMonitorTenant_IdempotentOnRepoll` |
| E-18 | A CT name is already an asset (scanned, imported, created by hand) | Not re-ingested; gets evidence only. With no attribution record it stays a legacy, confirmed asset (no demotion to needs_review) | `TestPromote_ExistingAssetKeepsStanding` |
| E-19 | A name appears only through a wildcard certificate (`*.wild.example.com`) | Kept as a `subdomain_discovered` exposure, not promoted: a wildcard proves nothing about that exact name | `TestPromote_StatesByRootOrigin` |
| E-20 | A name's newest certificate lapsed more than 90 days ago | Not promoted (a retired host); still a `subdomain_discovered` exposure for dangling-DNS work | `TestPromote_StatesByRootOrigin` |
| E-21 | Thousands of new names in one run | At most 500 new assets per tenant per run (`DefaultMaxPromotionsPerRun`), verified-root names first; the rest follow on later runs | `TestPromote_CapPrefersVerified` |
| E-22 | The same name under a verified and an unverified root | The stronger root wins (verified → confirmed) | `TestPromote_StatesByRootOrigin` (origin ranking), `TestMergeRoots` |
| E-23 | A promoted name's registrable parent does not exist yet | Ingest creates the parent domain only when the root is verified or already a domain asset; an unverified scope target never makes the platform invent a parent domain | `promotionReport` (`root_domain` only for verified/asset roots); scratch e2e (no extra root for the scope-target case) |
| E-24 | The promotion step fails after exposures were written | Logged; exposures stay; the next run retries (CT is re-read) | by construction (`MonitorTenant`) |
| E-25 | A scan's group contains only unconfirmed assets | The run is refused with `ALL_TARGETS_UNCONFIRMED`; mixed groups scan the confirmed members and warn with the skipped count | `TestResolveScanTargets_SkipsUnconfirmedGroupMembers`; scratch e2e |
| E-26 | The resolver answers SERVFAIL or times out | Outcome `unknown`: nothing raised, nothing resolved | `TestCheckDangling` (flaky name), `TestMonitorTenant_Lifecycle`, `TestQuery_TimeoutAndBadName`; scratch e2e |
| E-27 | A record is fixed, then breaks again | Auto-resolved with a history row; reopened (same fingerprint) only if this check resolved it | `TestMonitorTenant_Lifecycle`, `TestEASMDNSRepository`; scratch e2e |
| E-28 | A person accepts or resolves a DNS finding | Never reopened or re-resolved by the check | `TestMonitorTenant_Lifecycle`, `TestEASMDNSRepository`; scratch e2e (accepted stays accepted) |
| E-29 | Provider suffixes on the Public Suffix List's private section (`azurewebsites.net`) | Treated as provider-claimable names, not unregistered domains | `TestRegistrableDomain` |
| E-30 | SPF include loops, long include chains, records split into several strings | Each domain fetched once, at most 20 fetched; strings concatenated without separator (RFC 7208 §3.3) | `TestCheckEmail` (loop.com, many.com) |
| E-31 | Domain without mail (no MX or null MX) | Still expected to publish `-all` and an enforcing DMARC record; gaps are low | `TestCheckEmail` (parked.com) |
| E-32 | Truncated UDP answers | Retried over TCP | `TestQuery_TXTAndTCPFallback` |
| E-33 | Thousands of names / restarts / two replicas | 500 names per tenant per run, oldest-checked first; not due within 5/6 of the interval; per-tenant advisory lock per check | `TestEASMDNSRepository`, `TestMonitorTenant_LockedAndBudget` |
| E-34 | A subdomain-type or non-registrable domain asset for the email check | Skipped (`skipped_not_registrable`): subdomains inherit the organisation's DMARC | `TestMonitorEmail_FlagsWeakAndResolvesFixed` |
| E-35 | Two assets are merged (dedup review) | The kept asset gets the most recent human decision of either; without one it keeps its own record and merged automatic records are dropped (a legacy asset is never demoted); evidence moves, deduplicated, keeping the earliest first sighting; the kept asset's DNS-check state wins, a merged asset's state for a check the kept one never ran moves | `TestApproveAndMerge_KeepsAttributionDecisions`, `TestAssetMergeCoversEveryAssetReference` |
| E-17 | IDN names | CT logs carry the punycode (`xn--`) form, which is accepted as-is; Unicode forms are not produced by the sources | `TestCollectDiscoveries_DropsInvalidHostnames` |

## 3. Threat model of the EASM feature

Assets protected: tenant data (which domains a tenant watches is itself
sensitive), the platform's egress reputation, third parties' infrastructure,
and the platform itself against hostile data from external sources.

| # | Threat | Control | Test |
|---|---|---|---|
| T-1 | Cross-tenant leak: tenant A's discoveries stamped on tenant B, or B seeing A's monitoring state | The tenant comes from the asset/verified domain/scope target being queried, never from the CT answer; state rows keyed by `tenant_id` and read per tenant | `TestMonitorTenant_EmitsExposuresAndIsolatesTenant`, `TestCTMonitorStateRepository_RoundTripAndIsolation`; scratch e2e (second tenant's rows) |
| T-2 | SSRF through the configurable source URLs (DNS rebinding of `CERT_MONITOR_FEED_URL` / `CERT_MONITOR_CERTSPOTTER_URL`) | All CT traffic dials through `httpsec.SafeDialContext` (private/link-local/metadata refused unless the operator sets `OPENCTEM_HTTPSEC_ALLOW_PRIVATE`) | `TestQueryCRTSH_SSRFGuardBlocksInternal` |
| T-3 | Hostile data in CT answers (markup, control characters, over-long labels, names outside the tenant's domain) | Strict hostname syntax check; only the queried domain and names below it are accepted; the CT answer never chooses a tenant or an asset | `TestCollectDiscoveries_DropsInvalidHostnames`, `TestCollectDiscoveries_Subdomains`; scratch e2e (`junk*` domain) |
| T-4 | Resource exhaustion from a large or endless answer | 48 MiB body cap, 60 s request timeout, 10-page cap on Cert Spotter, 500 names per domain, 30-minute tenant budget | `TestMonitorTenant_SweepBudget`; `TestGet_RefusesOversizedBody` (a body past the cap is refused whole, never cut into parseable JSON); `TestMonitorTenant_EndlessBodyRaisesNothing` |
| T-5 | We hammer a public source (politeness) or get the platform's egress blocked | 1 s between queries, capped retries with jitter, `Retry-After` honored, failure back-off, 429 stops the fallback for the sweep, re-check age stops restart storms, one replica per tenant | `TestRetryDelay`, `TestMonitorTenant_BothSourcesFail_BacksOffAndSkips`, `TestMonitorTenant_RestartDoesNotRequery`, `TestMonitorTenant_SkipsWhenTenantLocked` |
| T-6 | A tenant uses EASM to probe infrastructure it does not own | CT monitoring is passive (T0): it only reads public logs and never contacts the names it finds. A name found only under a domain the tenant did not verify is `needs_review`, and scan target resolution (the single choke point for every scan run) skips asset-group members that are not confirmed; a failed attribution lookup stops the dispatch (fail closed). Direct targets the tenant types are its own assertion (O8) | `TestResolveScanTargets_SkipsUnconfirmedGroupMembers`, `TestAttributionRepository` (`ActiveCheckBlocked`); scratch e2e (needs_review member not in the command payload). *Planned*: the same gate on validation re-checks (RFC-011) and the P3 pipeline hops |
| T-9 | Cross-tenant attribution: evidence or a decision written on another tenant's asset id | Every write selects the asset with `tenant_id` in the same statement, so a foreign id writes nothing; reads are tenant-scoped; the API checks tenant and data scope first and answers 404 | `TestAttributionRepository`, `TestAssetAttributionHandler`; scratch e2e (other tenant gets 404) |
| T-10 | Automation silently re-confirms an asset a person rejected | Automatic writes skip rows with `decided_at`; automation only raises states; human decisions are audited (`asset.attribution_decided`) | `TestMerge`, `TestAttributionRepository`, `TestAssetAttributionHandler_Decide`; scratch e2e (re-sweep keeps the decision) |
| T-20 | The DNS checks probe infrastructure that is not the tenant's | DNS only, through the platform's resolver; never HTTP, never a packet to the target; CNAME targets are only looked up, not contacted; names with attribution `rejected` are skipped | `TestEASMDNSRepository` (rejected excluded), scratch e2e (no state row for the rejected name) |
| T-21 | Hostile or malformed DNS answers | Answers parsed with `x/net/dns/dnsmessage`; id must match; at most 64 records read; names lowercased and trimmed; only the configured resolver is trusted | `TestQuery_*` |
| T-22 | Resolver flooding / one tenant starving others | One limiter for all tenants (`EASM_DNS_QPS`), per-query timeout, per-tenant cap and budget | `TestQuery_RateLimited`, `TestMonitorTenant_LockedAndBudget` |
| T-23 | Cross-tenant: one tenant's DNS state or resolution touches another's exposures | All queries and updates carry `tenant_id`; state written only for the tenant's own asset | `TestEASMDNSRepository`; scratch e2e (tenant B isolated) |
| T-24 | Licence of the vendored fingerprint list | CC BY 4.0, attribution and source commit in `fingerprints/NOTICE.md` | `TestFingerprints_Load` (structure) |
| T-12 | The overview leaks assets outside a member's data scope, or another tenant's | Every asset-bound count and the top-risk list are narrowed to `user_accessible_assets` for a scoped member (unassigned exposures are hidden from them); all queries are tenant-scoped; the route sits behind the `attack_surface` module | `TestEASMSummaryRepository` (scoped member sees only its asset; other tenant's rows never counted); scratch e2e (other tenant's summary is 0) |
| E-36 | An asset a person marked as not ours (`rejected`) still has open exposures | Counted under attribution "rejected" only: excluded from the surface counts, new-asset windows, open exposures and top risks of the overview | `TestEASMSummaryRepository` |
| T-11 | Privilege: a read-only user changes attribution | `PUT` requires `assets:write` and passes the asset's data scope check | route registration (`assets:write`), `TestAssetAttributionHandler_Decide` (out-of-scope → 404) |
| T-7 | A tenant disables the attack-surface module but its domains are still sent to third parties | The controller skips tenants with `attack_surface` disabled | existing controller module-guard tests |
| T-8 | Disclosure of the tenant's domains to third-party sources | Only crt.sh and Cert Spotter (O1 free sources) receive domain names, over HTTPS by default; paid sources need tenant keys (P5). Recorded as a data-source decision in RFC-036 §12 | documented; no test |
