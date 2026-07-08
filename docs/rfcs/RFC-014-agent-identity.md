# RFC-014 — k8s-style agent identity (short-lived, auto-rotating credentials)

> Status: **Proposed** (design of record; phased implementation)
> Scope: authentication of **our agents** (phone-home scanners/runners/collectors).
> **Non-goal:** external connectors (DefectDojo/Jira/Nessus) — those keep the
> per-tenant AES-encrypted credential model + per-tenant webhook HMAC. Different
> threat model (we hold *their* creds; we can't impose our identity on a SaaS).

## Problem

An agent authenticates with a **per-agent API key** minted at creation/enrollment.
The current model is sound in its fundamentals but the credential is a **static,
non-expiring secret**:

- Each agent = one record with an inline `api_key_hash` + `api_key_prefix`
  (`pkg/domain/agent/entity.go`). Key = `rda_` + 32 bytes crypto/rand, hashed
  HMAC-SHA256 + server pepper, shown once (`agent/service.go:generateAgentAPIKey`).
- Auth: `AuthenticateByAPIKey` hashes the presented key → `GetByAPIKeyHash` →
  checks `Status.CanAuthenticate()` (active/disabled/revoked) → updates last_seen
  (`agent/service.go:354`).
- Enrollment tokens (`RegistrationToken`) are **already short-lived + use-limited
  + scoped** (`ExpiresAt`, `MaxUses`, `DefaultScopes`) — the k8s bootstrap-token
  analog, done right.
- **Rotation already exists**: `RegenerateAPIKey` + `POST /agents/{id}/regenerate-key`
  (admin, hard rotate).

### The real gaps (corrected)

An earlier read claimed "no rotation" — that was wrong (`RegenerateAPIKey`
exists). The genuine gaps, benchmarked against how k8s/SPIFFE do machine identity:

1. **No credential expiry.** The agent key never expires. A leaked key is valid
   forever until an admin manually regenerates. k8s issues **short-lived** certs
   (hours/days) and relies on TTL instead of a revocation list.
2. **No auto-renewal.** The agent can't renew its own credential; only an admin
   can regenerate (needs the agent id + `AgentsWrite`). k8s kubelet
   auto-rotates (`--rotate-certificates`) before expiry.
3. **No rotation overlap.** `RegenerateAPIKey` is a *hard* rotate — the old key
   dies instantly → brief agent downtime. A multi-key model gives overlap.
4. **Scoped per-key model is designed but unwired.** `pkg/domain/agent/api_key.go`
   (`APIKey` with `Scopes`, `ExpiresAt`, `LastUsedAt`, `UseCount`, `RevokedAt`,
   multi-key-per-agent) exists but nothing uses it; auth uses the single inline
   hash. `RunnerScopes/SensorScopes/…` are defined but not enforced.

## How the reference systems do it

| System | Enrollment | Credential | Rotation | Revocation |
|--------|-----------|-----------|----------|-----------|
| **k8s node/kubelet** | bootstrap token → CSR | client cert `system:node:<n>` | auto (`--rotate-certificates`) | short TTL + remove node |
| **k8s pod/ServiceAccount** | pod admission | **projected JWT**, ~1h, audience+pod-bound | kubelet auto-refresh at ~80% TTL | TTL + delete pod |
| **SPIFFE/SPIRE** | node+workload attestation | short-lived SVID (X.509/JWT) | auto | TTL |
| **GitHub Actions** | — | **OIDC token** (no stored secret) | per-run | ephemeral |
| **DefectDojo** | — | **per-user account token** (shared) | manual | manual |
| **OpenCTEM today** | ✅ registration token | ❌ static per-agent key | manual (hard) | status flag |

Verdict: the industry standard is **per-machine identity + short-lived
auto-rotating credential + enrollment**. A shared account token (DefectDojo) is
rejected — one leak compromises every agent, no per-agent revoke/audit. OpenCTEM
is already on the right axis; it just stops at a static key.

## Design

Adapt the k8s model **pragmatically to OpenCTEM's bearer-token reality** — no
mTLS/PKI needed; short-lived **signed/expiring keys** + the existing **lease**
heartbeat for auto-renew.

```
1. ENROLL   registration token (has ExpiresAt/MaxUses/Scopes) → per-agent identity
2. ISSUE    a credential with an ExpiresAt (e.g. 24h; configurable)
3. RUN      auth = hash lookup + Status.CanAuthenticate() + NOT expired
4. RENEW    agent calls POST /agents/renew with its current key → fresh key + exp
            (kubelet-style; driven off the lease heartbeat it already sends)
5. OVERLAP  wire agent.APIKey multi-key so renew issues key N+1 while N is still
            valid for a grace window → zero-downtime rotation + per-key audit
6. SCOPE    enforce RunnerScopes/SensorScopes (least privilege, like NodeRestriction)
7. REVOKE   short TTL = implicit; Status=revoked short-circuits immediately
```

Key inversion vs today: **after enrollment, issue a short-lived auto-renewing
credential instead of a permanent key.** A leaked key is then valid only until
the next renewal — self-revoking, no CRL (exactly how k8s avoids revocation lists).

### CI runners — OIDC federation (best-in-class, zero stored secret)

For ephemeral CI runners, follow GitHub/GitLab: the CI provider's **OIDC token**
is exchanged at OpenCTEM for a short-lived scoped agent token. **No secret stored
in CI.** OpenCTEM verifies the OIDC issuer/claims (repo, ref, workflow) and mints
a token scoped to that build. This is the strongest option for CI and a natural
extension of the token model.

## Phased implementation

Each phase is a focused PR → `develop`; the auth path + the agent repo's 5+ scan
sites are security-critical, so **no phase is rushed**.

| Phase | Work | Risk / notes |
|-------|------|-------------|
| **1a** ✅ | **Agent self-renew endpoint** `POST /api/v1/agent/renew` (auth by current key → new key), reusing `generateAgentAPIKey`+`repo.Update`. The auto-rotate building block. **Shipped #282.** | Additive, **no schema change**; works for tenant + platform agents. |
| **1b** ✅ | **Key expiry**: `agents.key_expires_at` column (migration 000185) + `Agent.IsKeyExpired()` + enforce in `AuthenticateByAPIKey`. Backward-compat: NULL = never expires. Renew sets a fresh expiry **only when `AGENT_KEY_TTL` is configured** (default off → no behavior change); the renew response returns `expires_at`. **Shipped this PR.** | Touched both agent scanners + INSERT/UPDATE/SELECT + auth path → DB round-trip test against the real schema. |
| **2** | **Auto-renew via lease**: agent renews before expiry off its existing lease heartbeat (kubelet-style). Enroll **all** agents (not just platform) so static keys shrink to ~0. | Reuses the lease system. |
| **3** | **Rotation overlap + per-key audit**: wire `agent.APIKey` multi-key (grace window, `LastUsedAt`/`UseCount`/IP). | New `agent_api_keys` table + repo. |
| **4** | **Scope enforcement** (`RunnerScopes/SensorScopes`) at the authz layer. | Least-privilege. |
| **5** | **OIDC federation for CI runners.** | Zero stored secret. |
| — | **External connectors unchanged** (per-tenant encrypted creds + webhook HMAC). | Correct as-is. |

## Testing

- 1a: renew returns a working new key; the old key stops authenticating; a
  disabled/revoked agent cannot renew.
- 1b: an expired key is rejected; NULL expiry authenticates (back-compat); renew
  refreshes expiry; the `key_expires_at` column exercised against the real schema.
- 3: overlap window keeps N valid while N+1 is issued; per-key last-used recorded.

CI must be green (`gh pr checks`) before any phase is called done. No
Generated-By/Co-Authored-By footers.
