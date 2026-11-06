### Added: one command and one approval to add a sensor

- **Sensors → Add sensor** offers one path: pick the platform, copy one command, paste it on the host. The command carries a single-use code so the dialog finds the sensor by itself; the sensor prints the same code, a link to approve it on and its fingerprint, and the command ends by itself once the sensor is paired. The choice between "create a pairing code first" and "pair a sensor that shows a code" is gone.
- New page **/activate**: the link a sensor prints (`<APP_URL>/activate?code=…`) opens the review; without a code it asks for the one the sensor printed. The page removes the code from the address bar and never approves on load.
- A start with a code uses it as the request's own code, so a command run after its code expired still pairs through the link. Every start without a token answers `user_code` and, when `APP_URL` is set, `verification_uri` and `verification_uri_complete`.
- The install commands write no local policy file: the sensor follows the organization's scope; the host owner may add a narrowing `/etc/openctem/sensor-policy.yaml` and the `STOP` kill switch at any time.

### Security: the approver picks the fingerprint the host shows

- The review offers three fingerprints, one of them the sensor's; the approval sends the picked one (`fingerprint`) and the API compares it with the sensor's. A wrong pick closes the request, is audited at high severity and notifies every administrator. This replaces the "fingerprint matches" tick (`fingerprint_confirmed` is no longer accepted).
- **Upgrade note:** API clients that approve pairings must send `fingerprint` (one of the review's `fingerprint_choices`). Sensors print the link from the sdk-go release that reads `verification_uri_complete`; older sensors still pair (the dialog finds them, or enter their code on /activate).
