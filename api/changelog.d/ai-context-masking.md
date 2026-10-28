### Security: every AI context bundle is masked, and only the platform can map it back

- Finding context built for an AI model replaces hosts, IP addresses and networks (class kept), e-mail addresses, user and organization names, URL ids and parameters and ticket ids with typed placeholders derived from a per-run secret key; the same value is a different placeholder in another run or organization. Secrets (credentials, tokens, private keys, cookies, session ids) are removed for good and never kept. Text that already looks like a placeholder is escaped first (except inside a secret, which is removed whole), unmasked fields from scanners or imports that carry a secret are withheld, and a placeholder the platform did not issue is never resolved in AI output.
- Fields are classed public, internal, restricted or tenant-only; a use case's ceiling decides what is sent and the rest is recorded as withheld. Restricted data is always fully masked; a leaked-secret finding never sends its snippet.
- The placeholder map of each run is stored encrypted with `APP_ENCRYPTION_KEY` (rekey registry), scoped to the organization, and purged after `AI_MASK_MAP_TTL` (default `168h`). Migration `20261028153737_ai_mask_maps`.

### Added: organization AI masking policy and preview

- `GET/PUT /api/v1/organization/settings/ai/masking`: which classes stay masked in internal data, a switch to mask subdomain labels too, and up to 200 extra terms. Owners and administrators; a change needs a recent sign-in and is audited (`ai_settings.masking_updated`, flagged when it masks less).
- `POST /api/v1/organization/settings/ai/masking/preview`: the exact masked context the AI would get for one finding the caller can read, with placeholders and their classes (never their values). Audited (`ai_settings.masking_previewed`).
