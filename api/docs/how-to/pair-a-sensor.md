# How to pair a sensor

Pairing connects a new sensor to your organization without any secret being
copied or pasted. The sensor creates its own key; you approve it in the
console after checking that both sides show the same fingerprint. Design:
[RFC-052](../rfcs/RFC-052-sensor-pairing-and-authorization.md).

You need the **Pair sensors** (`sensors:pair`) and **Approve sensors**
(`sensors:approve`) permissions (owners and administrators have both) and,
for the approval, your TOTP code or your password.

## 1. Install the sensor

Open **Sensors → Add sensor** (on an organization with no sensor yet, the
same panel is on the page). Pick where the sensor runs (Docker, Docker
Compose, Kubernetes or a Linux service) and how it joins (2a or 2b below);
the panel shows the exact command for this platform: the current release,
this instance's URL, the hardening (read-only root filesystem, no
capabilities, the checked seccomp profile) and the local policy file to save
next to it. The command contains no key. The sensor installation guide at
[docs.openctem.io/install](https://docs.openctem.io/install/) has the same
steps.

Keep the sensor's data directory on a persistent volume (one volume at
`/var/lib/openctem` in the container, holding `state/`, `outbox/` and
`content/`): the sensor's identity lives in `state/identity/`. The
directory must be `0700` and the files `0600`, owned by the sensor's user;
the sensor refuses to start otherwise and prints the command that fixes it.

Use a named volume (`-v openctem-sensor-data:/var/lib/openctem`, as the install
commands do): Docker creates it with the sensor's owner. A host directory
mounted instead must first be given to the sensor's user (`sudo chown -R
999:999 <dir>`; 1001 on the per-tool images, 65532 on the slim image), or the
sensor stops at start with the path, the owner and this fix. The complete
guide is [Run the sensor](https://docs.openctem.io/sensors/run-the-sensor/).

## 2a. Default: the sensor shows a code

Start the sensor (or run `openctemio-sensor pair`). It prints:

```
Pair this sensor in OpenCTEM → Sensors → Pair a sensor
  Code:        K7QM-4ZTD
  Fingerprint: 821 · melon · basil · bagel
  Key:         SHA256:UDDReOZl1ipXAfp9wYsm13sDBMK5og--QWdBjzuf6o4
  Expires:     10:42 (10 minutes)
```

In the console, open **Sensors → Add sensor**, choose **Pair a sensor that
shows a code** and type the code. The console shows the same fingerprint, the host name, OS and version
the sensor reported, and the address the request came from.

## 2b. Reverse: the console shows a code

Open **Sensors → Add sensor** and keep **Create a pairing code first**, then
**Create pairing code**. The command the panel shows now carries the code
(`SENSOR_PAIRING_CODE`, single use, valid 10 minutes); run it on the host
(`openctemio-sensor pair K7QM-4ZTD` does the same for an installed binary).
The panel waits live: as soon as the sensor connects it shows the
fingerprint to compare, then the approval, then the sensor online.

The panel's **Troubleshooting** section lists what the sensor log shows for
the common failures (a code that expired, a wrong clock, too many attempts,
the platform unreachable, the local policy missing) and the fix for each.

## 3. Compare and approve

1. **Compare the fingerprint** on the sensor's console with the one in the
   browser, word for word. If anything differs, **Deny**: someone else's
   sensor, or a machine between the sensor and the platform, made the
   request.
2. Check the host facts and the source address. An address you do not
   expect is a reason to deny.
3. Confirm that the fingerprint shown on the sensor console matches, choose the name, the role, the zones and
   the **grant profile**, enter your TOTP code or password, and **Approve**.

The sensor picks up its identity within a few seconds, confirms it, and
starts working. Every administrator gets a notification.

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
| The code is "not found" in the console | It expired (10 minutes), was used, or was mistyped. Restart the pairing on the sensor. |
| The sensor keeps waiting after you created an expectation | The code typed on the sensor was wrong; run `pair` again with the code from the console. |
| `certificate chain does not contain the pinned CA` | `SENSOR_CA_FINGERPRINT` does not match the certificate authority your platform presents, or a TLS-inspecting proxy sits in between. |
| `identity directory permissions` at start | Run the `chmod`/`chown` the sensor printed. |

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

