### Behaviour change: CTIS technical blocks are stored as flat asset properties

- Ingest, REST create/update and CSV import move a CTIS technical block's facts (`technical.certificate`, `.domain`, `.ip_address`, `.service`) to the asset type's flat property keys and drop the block (RFC-042 §6.3.10 item 6). `properties.certificate.not_after` is now `properties.not_after`, `properties.domain.registrar` is `properties.registrar`, a service's port is `properties.port`, and so on; renamed fields: `fingerprint` → `fingerprint_sha256`, `self_signed` → `is_self_signed`, `expired` → `is_expired`, `tls` → `has_tls`, `auth_required` → `is_auth_required`, service `name` → `service` (open port) or `server` (HTTP service).
- A domain's DNS records also give `dns_record_types`, `cname_target` and the A/AAAA addresses in `ip_addresses`. REST no longer writes the off-schema `record_type`, `ttl` and `dns_record_count`.
- A service's `tls: false` is no longer recorded (an unmeasured report sends the same value); `tls_cert_*`, `extra_info` and `auth_methods` are not kept.
- Migration `001334` promotes the blocks stored before (idempotent; its down is a no-op).
- **Upgrade note:** API clients reading `properties.<block>.<field>` read the flat key instead.
