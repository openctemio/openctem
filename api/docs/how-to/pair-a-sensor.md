# How to pair a sensor

Pairing connects a new sensor to your organization with one command on the
host and one approval in the console; no secret is copied or pasted. The
sensor creates its own key and prints a code and a link; you approve it
after picking the fingerprint the host shows. Design:
[RFC-052](../rfcs/RFC-052-sensor-pairing-and-authorization.md).

You need the **Pair sensors** (`sensors:pair`) and **Approve sensors**
(`sensors:approve`) permissions (owners and administrators have both) and,
for the approval, your TOTP code or your password.

## 1. Run one command

Open **Sensors → Add sensor** (on an organization with no sensor yet, the
same panel is on the page). Docker is preselected; pick Docker Compose,
Kubernetes or a Linux service if the sensor runs there. The panel shows one
command for that platform: the current release, this instance's URL, the
hardening (read-only root filesystem, no capabilities, the checked seccomp
profile), this platform's private certificate authority when it has one
(with its SHA-256 fingerprint under the command) and a single-use pairing
code. The command contains no key and asks you to edit nothing. This page is
the single source for the install steps; the guide at
[docs.openctem.io/install](https://docs.openctem.io/install/) links here.

Copy it and paste it on the host. It installs and starts the sensor, then
shows what the sensor prints and **ends by itself once the sensor is
paired** (Ctrl-C only stops watching; the sensor keeps running):

```
Pair this sensor: open https://ctem.example.com/activate?code=K7QM-4ZTD
  Code:        K7QM-4ZTD
  Fingerprint: 821 · melon · basil · bagel
  Key:         SHA256:UDDReOZl1ipXAfp9wYsm13sDBMK5og--QWdBjzuf6o4
```

No local policy is needed: the sensor scans only what your organization's
scope allows. The host owner may narrow it on the host (optional, below).

Keep the sensor's data on a persistent volume (one volume at
`/var/lib/openctem` in the container, holding `state/`, `outbox/` and
`content/`): the sensor's identity lives in `state/identity/`. The commands
use a named volume, which Docker creates with the sensor's owner. A host
directory mounted instead must first be given to the sensor's user (`sudo
chown -R 999:999 <dir>`; 1001 on the per-tool images, 65532 on the slim
image), or the sensor stops at start with the path, the owner and this fix.

## 2. Approve it

The Add sensor panel finds the sensor by itself (the command's code tells
the platform which panel is waiting for it). A sensor started any other way
(from the docs, `sensors.sh add`, Helm) prints its own code and link: open
the link, or open **/activate** and type the code. Both show the same
review:

1. **The organization** the sensor joins, named at the top. If the sensor is
   meant for another organization, switch to it first; an approval after a
   switch of organization is refused.
2. **Who and where**: host name, system, product and version, the address
   the request came from (private network, public internet, or a known
   provider) next to **your** address, and how long ago it started. A host
   you do not recognise, an address you do not expect, or a request you did
   not start just now: **Reject**. Never approve a link or a code someone
   sent you by email, chat or phone.
3. **Pick the fingerprint the host shows**, out of three. Look at the host's
   screen, not at a message. A wrong pick **closes the request** and tells
   every administrator; if you started the sensor, it shows a new code and
   link a moment later.
4. The name is prefilled from the host name. **More options** holds the
   role, the grant profile and the scan zones; the defaults fit a scanner
   inside your network.
5. Enter your TOTP code or password (nothing when you signed in less than 10
   minutes ago) and **Approve**.

The sensor picks up its identity within a few seconds, confirms it, and
starts working. Every administrator gets a notification.

Automation keeps the code-first path: create a code with `POST
/api/v1/sensor-pairings/expectations` and start the sensor with
`SENSOR_PAIRING_CODE` (or use an enrollment token, below).

### Narrow it on this host (optional)

The host owner may restrict the sensor further than the organization's
scope: write `/etc/openctem/sensor-policy.yaml` (the panel's **Narrow it on
this host** fold has a starting point) and restart the sensor. The file can
only narrow; the platform never writes it. `sudo touch /etc/openctem/STOP`
stops every job while the file exists.

## 4. What the new sensor may do

A newly paired sensor is at trust level **New**: it gets passive (T0) jobs
only, no credentials, and cannot send results without a job. Open the sensor,
review its **Grant**, narrow it if you need to, and **Promote to Trusted**
when you are satisfied (this needs the **Widen sensor grants** permission).

| Profile | For |
|---|---|
| `internal-network-scanner` (default for a scanner) | A scanner in one network zone (active, non-intrusive checks) |
| `easm-external` | Internet-facing assets only |
| `authenticated-scanner` | Scans that need credentials (only once Trusted) |
| `collector` / `collector:<integration>` (default for a sensor approved with role collector) | A collector or connector, no target scanning; results without a job allowed once Trusted |
| `ci-runner` | Code scanning in a pipeline |
| `endpoint-agent` | The local host only |

## Re-pairing a sensor

If a sensor's key is lost or may be stolen, pair it again as the same sensor:
the pairing request names the existing sensor (`repair_sensor_id` on
`POST /api/v1/sensor-pairings/expectations`, or the sensor's own re-pairing
request), and the console marks the request **Re-pairing <name>**. How to
start a re-pairing on the host is in the sensor's documentation. Approve it
like a new pairing. The old keys are revoked at once, the history is kept, and
the sensor returns to trust level New.

## Bearer keys

New organizations cannot create sensors with an API key (`octs_…`); pairing is
the only way in. Existing organizations keep the option (the sensor identity policy
switch in the organization settings), and their existing key-based sensors
keep working, marked "legacy key". Turning on **Require key-bound identity** stops new keys from
being created.

## Troubleshooting

| Symptom | Cause |
|---|---|
| The code is "not found" | It expired (10 minutes), was used, or was mistyped. The sensor starts a new request by itself and prints a new code and link. |
| The panel says the command's code expired | You ran the command late: the sensor still prints that code and a link; open the link. Or click **New command**. |
| The sensor says another fingerprint was picked | Someone picked a fingerprint the host did not show; that request was closed. Open the new link the sensor prints and pick the fingerprint on this host. |
| `x509: certificate signed by unknown authority` | The platform uses a private certificate authority the host does not trust. The sensor stops and prints the authority's SHA-256 fingerprint: compare it with the one under the console's command, then use the console's command (it carries the authority) or `SENSOR_CA_CERT_FILE`. |
| `certificate chain does not contain the pinned CA` | `SENSOR_CA_FINGERPRINT` does not match the certificate authority your platform presents, or a TLS-inspecting proxy sits in between. |
| `identity directory permissions` at start | Run the `chmod`/`chown` the sensor printed. |
| The sensor was stopped before you approved it, or you made a new code | Start it again with the new code (`./sensors.sh pair NAME --pairing-code XXXX-XXXX` in the multi-sensor kit). The sensor keeps its key; the new start closes its earlier request that nobody approved, and you approve the new one. Started again with the same code, it re-uses that request: compare the fingerprint again after it reappears. |
| The sensor says its key is already registered (`pairing-key-registered`) | That key was approved once (even if the sensor never finished, or the key was revoked later); a key never pairs twice. Restore the sensor's identity directory, or remove its key so it generates a new one, then pair with a new code. |
| The sensor is rate limited (`429`) after a few failed starts | The start budget per code is 5 per hour (burst 3); wait for the `Retry-After` it was given, or make a new code. |

## Many sensors: enrollment tokens

To install many sensors without approving each one (Kubernetes, Terraform,
a fleet of hosts), open **Sensors → Enrollment tokens → Create token**
(needs **Approve sensors** and a recent sign-in). Choose the expiry, how many
sensors it may enroll, the scan zones, the grant profile, optional labels,
optional allowed source addresses, and whether each sensor still needs your
approval. The token is shown once: put it in a root-only file (or a
Kubernetes Secret) and point the sensor at it with
`SENSOR_ENROLLMENT_TOKEN_FILE` (sensor releases with sdk-go that reads
`SENSOR_ENROLLMENT_TOKEN`; older sensors cannot use organization tokens). Each sensor that starts with it
joins the organization at trust level New; you are notified of every
enrollment and can revoke the token at any time.

