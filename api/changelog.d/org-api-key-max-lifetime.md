### Security: Organization maximum API key lifetime (default 90 days) and an expiry notice

- New keys may live at most the organization's maximum: 90 days by default, settable from 1 day up to the platform ceiling of 365 days (`GET`/`PUT /api/v1/organization/settings/api-keys`). Before, every key could live a year. Create refuses a longer `expires_in_days` from every entry point (API keys, service accounts, MCP connection key); a policy that cannot be read refuses.
- Raising the maximum needs a recent sign-in, is audited high (`tenant.api_key_policy_updated`) and every owner and administrator is told; lowering it applies at once.
- Existing keys keep their expiry; one minted for longer than the current maximum is flagged (`exceeds_org_max`, "Over the maximum" in Settings > API keys).
- A week before a key expires, the person who minted it gets one in-app notice. Migration 20261031060420 adds `api_keys.expiry_notified_at` (nullable, no backfill).
- Settings > API keys has a Maximum key lifetime card; the key dialogs offer only lifetimes within the maximum.
