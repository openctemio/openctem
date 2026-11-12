### Security: the platform signs everything a sensor pins at pairing

- The approval and confirm answers of sensor pairing (`GET` and `POST
  .../complete` under `/api/v2/sensor/pairings/{id}`) carry `grant`: the
  identity with its content-signing keys, the job signer's keys and key set
  (the hello's `signed_jobs` block) and, with `PLATFORM_CA_CERT_FILE`, the
  root CAs of the platform's TLS certificate, signed with the platform
  pairing key whose fingerprint the administrator compares. The statement
  names the pairing, the sensor's key and its revealed nonce, so it cannot be
  replayed to another sensor.
- Before, only the start answer was signed: someone in the middle of a first
  pairing could relay it untouched and swap the job-signing keys, the content
  keys or the TLS anchor the sensor learned afterwards.
- **Upgrade note:** sensors built on the sdk-go release with signed pairing
  answers refuse to pair with a platform without this change ("upgrade the
  platform"). Sensors from before it ignore the new member and pair as
  before. Already paired sensors are unaffected.
