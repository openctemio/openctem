# Agent Identity & Credentials

> Design of record: [RFC-014](../rfcs/RFC-014-agent-identity.md).
> This document tracks **what is shipped vs planned** for how our agents
> authenticate. It does **not** cover external connectors (DefectDojo / Jira /
> Nessus) — those keep the per-tenant AES-encrypted credential + webhook-HMAC
> model, a different threat model (we hold *their* secret; we cannot impose our
> identity on a third-party SaaS).

## Model in one paragraph

Every agent has its **own identity** — one `agents` row with an inline
`api_key_hash` (HMAC-SHA256 + server pepper of an `rda_`-prefixed 32-byte random
key, shown once at issue). This is deliberately **not** a shared account: one
leaked key revokes/audits independently, unlike a single tenant-wide token. On
top of that identity the credential is evolving from a *static* secret toward a
**short-lived, auto-rotating** one — the kubelet / ServiceAccount model — so a
leaked key self-revokes at its next renewal instead of living forever.

## Lifecycle

```
ENROLL   registration token (ExpiresAt / MaxUses / DefaultScopes)   [shipped]
   │       → mints a per-agent identity + first API key
ISSUE    api_key_hash + api_key_prefix, optional key_expires_at     [shipped]
RUN      auth = peppered-hash lookup
         → Status.CanAuthenticate()  (active / disabled / revoked)
         → NOT expired (key_expires_at)                             [shipped 1b]
RENEW    agent POSTs /api/v1/agent/renew with its current key       [shipped 1a]
         → fresh key (+ fresh expiry when a TTL is configured)
ROTATE   admin POST /agents/{id}/regenerate-key (hard, tenant)      [shipped]
REVOKE   Status = revoked  → auth short-circuits immediately        [shipped]
         short key TTL      → implicit revocation (no CRL)           [shipped 1b]
```

## What is shipped

| Capability | Where | Notes |
|-----------|-------|-------|
| Per-agent identity + peppered hash | `internal/app/agent/service.go` (`generateAgentAPIKey`, `AuthenticateByAPIKey`) | `crypto.HashTokenPeppered`; legacy plain-SHA256 fallback for pre-pepper rows |
| Enrollment tokens (short-lived, use-limited, scoped) | `pkg/domain/agent/registration_token.go` | the k8s bootstrap-token analog |
| Admin hard rotation | `POST /agents/{id}/regenerate-key` (JWT, `AgentsWrite`) | old key dies immediately; tenant-scoped |
| **Agent self-renew** (Phase 1a) | `POST /api/v1/agent/renew` (agent API-key auth) → `AgentService.RenewAPIKey` | agent rotates its **own** key; works for tenant **and** platform agents; TOCTOU-safe (re-reads status by id) |
| **Key expiry** (Phase 1b) | `agents.key_expires_at` (migration `000185`), `Agent.IsKeyExpired()`, enforced in `AuthenticateByAPIKey` | **NULL = never expires** (default + all legacy rows) |
| Configurable key TTL | `AGENT_KEY_TTL` env → `AgentService.SetKeyTTL` | **default `0` = disabled**; only self-renew honors it |

### Enabling short-lived credentials (`AGENT_KEY_TTL`)

Set e.g. `AGENT_KEY_TTL=24h`. Then every call to `/api/v1/agent/renew` issues a
key that expires in 24h, and the renew response includes `expires_at` so the
agent can schedule its next renewal. With the variable **unset (the default),
renewed keys never expire** and behavior is identical to before Phase 1b.

> **Operational prerequisite.** Do **not** enable a TTL until agents actually
> auto-renew (Phase 2). A configured TTL only sets expiry *on renewal*, and an
> agent that never renews would simply keep its non-expiring key — but an agent
> that renews once and then stops would lock itself out at expiry. Treat TTL as
> off until the daemon renew loop ships.

## What is planned (not yet shipped)

| Phase | Capability | Scope |
|-------|-----------|-------|
| **2** | Daemon agents auto-renew off their existing lease heartbeat (kubelet-style, before expiry) | **cross-repo** — `sdk-go/pkg/platform/lease.go` renew loop + credential swap + persistence, then agent bump |
| **3** | Rotation overlap + per-key audit — wire the designed-but-unwired multi-key model (`pkg/domain/agent/api_key.go`: `Scopes`, `ExpiresAt`, `LastUsedAt`, `UseCount`) | new `agent_api_keys` table + repo; auth checks N and N+1 in a grace window (zero-downtime rotation) |
| **4** | Scope enforcement (`RunnerScopes` / `SensorScopes`) at the authz layer | least-privilege, like k8s NodeRestriction; rides on the Phase-3 multi-key |
| **5** | OIDC federation for ephemeral CI runners — exchange the CI provider's OIDC token for a short-lived scoped agent token | zero stored secret; strongest option for CI |

## Why not a shared account token

A single tenant-wide (or global) token — the DefectDojo model — is rejected: one
leak compromises **every** agent, with no per-agent revoke, no per-agent audit,
and no way to scope one runner differently from another. Per-machine identity +
short-lived rotating credential is the industry standard (k8s node certs, k8s
ServiceAccount projected JWTs, SPIFFE SVIDs, GitHub Actions OIDC). OpenCTEM was
already on that axis; Phases 1a–1b close the "static key that never expires" gap.
