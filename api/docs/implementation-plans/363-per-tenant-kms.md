# #363 — Per-Tenant KMS (Data-Residency Opt-In)

- **Q/WS**: Q4 / WS-F
- **Status**: Pending — blocked on KMS backend decision + cryptographic design review
- **Seam**: to be created — `pkg/crypto/envelope` (no code exists yet)
- **Related**: existing `APP_ENCRYPTION_KEY` (single AES-256-GCM key for ALL tenants) in `pkg/crypto/` — this task replaces it for opted-in tenants.

## 1. Problem

Today every tenant's sensitive data (integration credentials, OAuth tokens, encrypted webhooks) is encrypted with a **single shared AES-256-GCM key** loaded from `APP_ENCRYPTION_KEY` env. Consequences:

1. **Blast radius**: one key leak compromises all tenants' secrets.
2. **No data-residency**: key material lives in our VPC, not the tenant's region.
3. **No BYOK** (bring-your-own-key): compliance-heavy tenants (financial, healthcare, EU-only) cannot meet their regulatory requirements to hold their own keys.
4. **No rotation story**: rotating the shared key re-encrypts every row across all tenants in one go.

## 2. Decision needed FIRST (before coding)

**Backend choice.** Each option has different API shape, latency, cost model. Pick one primary, optionally one for on-prem:

| Option | Primary | On-prem | Notes |
|---|---|---|---|
| AWS KMS (customer-managed CMK) | ✅ strong candidate | ❌ | Native per-tenant CMK, CloudTrail audit trail built in, multi-region replication. Cost: $1/CMK/month + $0.03/10K requests. |
| GCP KMS | ✅ strong candidate | ❌ | Similar shape to AWS KMS. Use if our primary cloud is GCP. |
| Azure Key Vault | possible | ❌ | Required if EU Sovereign Cloud tenants sit in Azure. |
| HashiCorp Vault Transit | ✅ for on-prem | ✅ | Customer-managed Vault cluster can sit in customer's VPC → data-residency by default. More ops overhead. |
| PKCS#11 HSM (Thales, Safenet) | ❌ rare | ✅ rare | For regulated tenants (PCI-DSS L1, FedRAMP High). Very slow, very painful to operate — defer unless a specific deal requires it. |

**Recommendation to decide on:** AWS KMS as primary (we're AWS-native), Vault Transit as on-prem option, defer Azure/GCP/HSM until a tenant asks. Write this down and stop moving it.

## 3. Scope (after decision)

**Ships:**
- `pkg/crypto/envelope/` — generic envelope encryption API (encrypt with a per-tenant Data Encryption Key (DEK), wrap DEK with tenant's Key Encryption Key (KEK) held by KMS).
- Two backends: `envelope/awskms/` and `envelope/vault/`.
- Migration `000157_tenant_kek_refs.up.sql` — add `tenants.kek_alias` + `tenants.kek_provider` (nullable; NULL = fall back to shared `APP_ENCRYPTION_KEY`).
- Encrypted columns audit — every encrypted column gets a new sibling `*_kek_alias` column so decrypt knows which KEK to call.
- Re-encrypt controller — when a tenant flips to KMS, a background job re-encrypts existing rows.
- CLI tool `bin/kek-rotate --tenant=<id>` — manual key rotation.

**Does NOT ship:**
- Automatic periodic rotation — v1 is operator-triggered. Auto-rotate is a follow-up after we trust the rotate path.
- Cross-region KEK replication — v1 single region per tenant.
- Client-side encryption (user's browser holds the key) — different threat model, out of scope.

## 4. Cryptographic design

### 4.1 Envelope scheme

```
┌─────────────────────────────────────────────────┐
│  Per row / per payload:                          │
│                                                  │
│   plaintext  ──[AES-256-GCM(DEK)]──► ciphertext │
│      DEK     ──[KMS Encrypt(KEK)]──► wrapped_DEK│
│                                                  │
│  Stored in DB:                                   │
│   ciphertext || wrapped_DEK || nonce || ver      │
└─────────────────────────────────────────────────┘
```

- **DEK**: 256-bit AES key, generated per-row via `crypto/rand.Read` at encrypt time.
- **KEK**: managed by KMS backend, tenant-owned, never leaves KMS (only wrap/unwrap operations).
- **Algorithm**: AES-256-GCM for payload; KMS wraps via its native algorithm (AWS KMS: AES-256-GCM; Vault Transit: `aes256-gcm96` or `chacha20-poly1305`).
- **Nonce**: 96-bit random per-encryption (never reuse for same DEK; since DEKs are per-row, reuse risk is effectively zero).

### 4.2 Version / migration byte

Prepend a **single byte** `version` to every ciphertext:
- `0x00` — legacy, shared `APP_ENCRYPTION_KEY` (existing rows; backward compat).
- `0x01` — envelope, AWS KMS wrap.
- `0x02` — envelope, Vault Transit wrap.

Decrypt dispatches on the version byte. This is how existing rows coexist with newly-encrypted rows without a big-bang re-encrypt.

### 4.3 Wire format (binary)

```
┌────────┬────────────────┬──────────┬──────────┐
│ ver(1) │ wrapped_dek(N) │ nonce(12)│  ct + tag │
└────────┴────────────────┴──────────┴──────────┘
```

N is variable — AWS KMS ciphertext can be ~150-300 bytes. Prepend a uvarint length.

### 4.4 Failure modes

| Failure | Behaviour |
|---|---|
| KMS unreachable at encrypt | Encrypt MUST fail hard (do not silently fall back to shared key — that's a downgrade attack). Retry with backoff, surface as operator alert. |
| KMS unreachable at decrypt | Same — fail the read. Integration using that credential goes into `degraded` state. Do NOT serve plaintext. |
| Tenant KEK disabled / deleted | Return specific error `ErrKEKUnavailable` — admin UI shows "restore your KMS key to regain access". |
| DEK unwrap returns invalid DEK | Reject — do NOT decrypt with garbage key. Audit log + alert. |

### 4.5 DEK caching

**Decision needed:** cache unwrapped DEKs in memory to avoid per-read KMS calls?
- **Pro**: cuts KMS cost + latency by ~95% for hot rows.
- **Con**: DEK in process memory widens blast radius if the API process is compromised.

**Default:** cache DEKs in a LRU for 5 minutes, cap 10K entries, evict on tenant-key-rotation event. Document this knob in the security doc so compliance-heavy tenants can set TTL=0.

## 5. DB schema changes

Migration `000157_tenant_kek_refs.up.sql`:

```sql
ALTER TABLE tenants
    ADD COLUMN kek_provider TEXT,   -- 'awskms' | 'vault' | NULL
    ADD COLUMN kek_alias    TEXT,   -- KMS key ARN / Vault key name
    ADD COLUMN kek_region   TEXT;   -- e.g. 'eu-west-1' (data-residency pin)

-- Sibling columns on every encrypted column so decrypt knows how to dispatch.
-- Add to each of these tables (there are ~8 today — grep `credentials_encrypted`):
ALTER TABLE integrations
    ADD COLUMN credentials_kek_alias TEXT;

-- Back-fill: NULL kek_alias means "use version byte 0x00 (legacy shared key)".
```

Grep target: every column named `*_encrypted` in the schema gets a matching `*_kek_alias` column.

## 6. Public interface

```go
// pkg/crypto/envelope/envelope.go
package envelope

type Encryptor interface {
    // Encrypt wraps plaintext with a fresh DEK, the DEK with the tenant's KEK.
    // Returns the versioned wire format (see §4.3).
    Encrypt(ctx context.Context, tenantID shared.ID, plaintext []byte) ([]byte, error)

    // Decrypt dispatches on the version byte and returns plaintext.
    Decrypt(ctx context.Context, tenantID shared.ID, ciphertext []byte) ([]byte, error)

    // Rewrap is used by the re-encrypt controller: decrypt with current KEK,
    // re-encrypt with the new KEK. Does NOT expose plaintext to caller.
    Rewrap(ctx context.Context, tenantID shared.ID, oldCiphertext []byte) (newCiphertext []byte, err error)
}

// Config sources:
//   - TenantKEKRepository — reads kek_provider/kek_alias/kek_region from tenants table.
//   - KMSClientFactory     — produces a backend client per tenant (AWS KMS with assumed-role, Vault Transit).
```

### 6.1 Integration with existing encryption

Replace calls to `pkg/crypto.Encrypt` / `pkg/crypto.Decrypt` with `envelope.Encryptor.Encrypt(ctx, tenantID, plaintext)`. Wherever the callsite doesn't already have `tenantID` in context, that's a red flag — audit the callsite.

### 6.2 Fallback

`Encryptor` implementation for tenants where `kek_provider IS NULL` uses `APP_ENCRYPTION_KEY` and writes version byte `0x00`. Existing rows keep working.

## 7. Re-encrypt controller

Background job `internal/infra/controller/kek_rewrap.go`:

```go
// When tenant flips to KMS (sets kek_alias), enqueue a job.
// The job walks every encrypted column for that tenant, Rewrap()s each row,
// commits in batches of 100.
// Per-row lock: SELECT ... FOR UPDATE SKIP LOCKED so concurrent writes don't race.
// Resumable: job writes progress to `tenant_kek_migration` table (tenant_id, table, last_id).
```

Estimated time: at 1000 rewraps/sec, a tenant with 1M encrypted rows takes ~17 min. Runs in background; tenant can operate throughout (reads use version byte to dispatch; writes use the new KEK immediately for new rows).

## 8. Test plan

### 8.1 Unit
- `TestEncryptDecrypt_Roundtrip` — each backend (awskms, vault, legacy).
- `TestVersionByte_Dispatch` — hand-crafted ciphertext with each version byte → correct backend invoked.
- `TestEncrypt_KMSFails_HardError` — fake KMS returns error → Encrypt returns error, NO shared-key fallback.
- `TestDecrypt_UnknownVersion_Rejected`.
- `TestRewrap_NoPlaintextLeak` — rewrap path, assert plaintext never escapes `Rewrap` call (via memory audit assertion helper).
- `TestDEKCache_ExpiresOnRotation` — emit key-rotation event, assert cache cleared.

### 8.2 Integration
- **awskms backend**: requires localstack (has KMS) or real sandbox. Create KEK, encrypt 100 payloads, decrypt, assert.
- **vault backend**: spin up Vault dev server in docker-compose, enable transit, create key, run roundtrip.

### 8.3 Threat-model tests (security review checklist)
- Attempt to decrypt tenant A's ciphertext with tenant B's KEK → must fail (KMS rejects because KEK ID mismatches).
- Replay attack: submit same nonce twice to the same DEK → must fail (this requires DEK reuse which we prevent by per-row DEKs; add the test anyway as a regression guard).
- Downgrade attack: craft a ciphertext with version byte `0x00` for a tenant that has `kek_provider=awskms` → policy check: reject. Encryptor MUST refuse to decrypt legacy format once a tenant has opted in (after migration finishes).

## 9. Rollout

1. **Phase 1**: Land `envelope` package + legacy backend only. No KMS integration yet. Swap every `crypto.Encrypt` callsite. Verify zero behaviour change in prod.
2. **Phase 2**: Land awskms backend + AWS KMS CMK-per-tenant provisioning flow in tenant-admin API. Ship with feature flag `kms.per_tenant.enabled=false`. Internal test.
3. **Phase 3**: One pilot tenant opts in. Run rewrap job, watch metrics (`ctem_kms_wrap_duration_seconds`, error rate), for 2 weeks.
4. **Phase 4**: GA — expose opt-in in tenant settings UI.
5. **Phase 5**: Vault backend for on-prem deployments.

## 10. Open questions

| # | Question | Who decides | Default |
|---|---|---|---|
| Q1 | Primary backend: AWS KMS or Vault? | Platform + Security | AWS KMS primary, Vault for on-prem |
| Q2 | DEK cache TTL | Security | 5 min, configurable to 0 |
| Q3 | Per-column KEK or per-tenant KEK? | Security | Per-tenant KEK, per-row DEK. Simpler ops. |
| Q4 | Key rotation cadence — operator-triggered only, or scheduled? | Security | v1 operator-only; v2 scheduled quarterly |
| Q5 | How to handle tenant offboarding — destroy KEK? | Legal + Security | Schedule KEK deletion after 30-day retention (KMS's "pending deletion" state) |
| Q6 | Audit log: log every wrap/unwrap call? | Security | CloudTrail / Vault audit already does this — don't duplicate |
| Q7 | Region pinning: can tenant choose `eu-west-1` vs `us-east-1`? | Product | Yes — `kek_region` column supports it |
| Q8 | What happens to replicated / backup data encrypted under tenant KEK if tenant deletes their KEK? | Legal | Document: "your backup is cryptographically shredded — we cannot recover it" |

## 11. Non-goals

- Client-side encryption (browser-held keys).
- Homomorphic encryption / confidential computing.
- Per-user (as opposed to per-tenant) keys.
- Automatic scheduled rotation in v1.
- Key escrow / legal-hold workflows.
- Multi-region active-active KEK replication.

## 12. Prior art / references

- AWS KMS envelope-encryption pattern: https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#enveloping
- HashiCorp Vault Transit: https://developer.hashicorp.com/vault/docs/secrets/transit
- Google Tink library (rejected — Go support is thinner than our needs, adds dep weight).
- Existing project encryption: `pkg/crypto/aes.go` — what we're replacing.
