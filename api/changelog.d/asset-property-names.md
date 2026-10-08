### Behaviour change: asset property names follow one convention

- Booleans are `is_<state>` / `has_<thing>`, timestamps `<event>_at`, lists plural; the registry generator refuses a key that breaks this (RFC-042 §6.3.10, architecture page "Property names").
- 22 boolean keys, 3 timestamps and one duration were renamed (`mfa_enabled` → `has_mfa`, `encrypted` / `encryption_enabled` → `is_encrypted`, `publicly_accessible` → `is_public`, `last_login` → `last_login_at`, `max_session_duration` → `max_session_duration_seconds`, …). The old names stay accepted on every write path and are folded into the new key.
- Scanner spellings fold too: `os` → `os_name`, `web_server` → `server`, `self_signed` → `is_self_signed`.
- Network devices gain `vendor`, `model`, `firmware_version`, `management_ip` and `serial_number`; HTTP services `chain_status_codes`.
- Migration `001333` folds the old names in stored assets (idempotent; its down is a no-op because a fold is not reversible).
- **Upgrade note:** API clients and saved filters that read the old key names must read the new ones; writes with the old names keep working.

### Security: `GET /api/v1/assets/stats?count_by=` is capped

- `count_by` accepts only property keys of the schema (a synonym counts as its key), at most 10. Each field was one more GROUP BY over the caller's assets, and the list was unbounded.
