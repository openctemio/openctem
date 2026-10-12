### Security: custom template trust (RFC-038 §6.12)

- **Custom templates reach sensors only in a signed manifest.** Every
  command poll signs one DSSE envelope per command (Ed25519 over the exact
  bytes) listing the tenant, the polling sensor, the command, a 1-hour
  expiry and the SHA-256 of every template; templates are validated again
  first, and a set that fails is sent unsigned so the sensor refuses it.
  Keys are per tenant, derived from `APP_TEMPLATE_SIGNING_KEY` (new;
  unset: derived from `APP_ENCRYPTION_KEY`). New
  `GET /api/v1/scanner-templates/signing-key` returns the tenant's public
  key to pin on its sensors (`SENSOR_TEMPLATE_SIGNING_KEYS`). **Upgrade
  note:** sensors on the matching sdk-go refuse custom templates until the
  key is pinned; scans without custom templates are unaffected.
- **More nuclei protocols refused at upload.** The `file` protocol (reads
  the sensor's disk) and self-contained templates are refused like `code`,
  `javascript` and `headless` already were, with an error naming the
  protocol.
