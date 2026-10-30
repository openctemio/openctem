# How to mark things out of scope, and how it reaches sensors

> Tenant how-to: the ways to say "do not scan this", what each one does, and
> every place the platform and the sensor enforce it. Design:
> [RFC-054](../rfcs/RFC-054-scope-model.md) (§6.5 refusals, §15 inventory
> first, §16 unclassified assets); architecture:
> [active-probe-gate.md](../architecture/active-probe-gate.md).

---

## 1. Pick the right tool

| You want | Use | Who | Effect |
|---|---|---|---|
| Never scan a name, address, range, URL or path, whoever owns it | **Exclusion** (Scoping > Out of scope > Add, or the inventory's bulk **Mark out of scope > Exclude**) | scope write; in the Strict scan approval mode it waits for an exclusion approver other than you | Wins over every scope entry and every setting. Scans leave the target out, and ranges are cut around it. |
| Say an asset is not your organization's | **Not ours** (asset Ownership tab, the inventory's bulk **Mark out of scope > Not ours**, or the addresses card on Attack surface > Suggestions) | assets write | The asset (and names under a rejected name) is never actively scanned and never suggested again. Undo forgets the decision. |
| Stop scanning something that is in scope | Remove or deactivate its **scope entry** (Scoping > In scope) | scope delete / approve | Unclassified assets may still get low-impact checks (section 4); add an exclusion to stop those too. |
| Keep an asset in the inventory but out of sight | **Archive** (inventory) | assets write | Hides it from the default list; it does not change scanning. |

Every exclusion has a **kind**: *Do not scan* (the default: yours, but must
not be scanned; its findings stay open), *Not ours* or *Retired*. A
permanent Not ours or Retired exclusion closes the open findings of what it
matches as **Asset out of scope** (never counted as fixed), and their tasks,
tickets and SLA clocks follow; removing it, giving it an end date or changing
it to Do not scan reopens them. "Not ours" on an asset does the same for
that asset. An exclusion with an end date only pauses scanning.

Only decisions made after the feature went live close findings: an asset
already marked "Not ours" before then stays unscanned and keeps its findings
open until someone decides again. With limited data access (no full data
access) you can close findings only with an exact rule (one hostname or IP
address, no wildcard, network or range), because a broader rule is matched
again on every pass and would also reach assets you cannot see; ask someone
with full data access for those.

Every action in the inventory answers with an Undo toast. Undoing an
exclusion widens scope, so it asks you to re-authenticate.

## 2. Exclusion kinds

| Kind | Pattern | Matches |
|---|---|---|
| Domain | `old.example.com`, `*.legacy.example.com` | the name exactly, or every name under the wildcard; URLs and `host:port` on those names too |
| IP address | `203.0.113.5` | that address, inside any range target as well |
| IP range / CIDR | `203.0.113.0/28`, `203.0.113.10-203.0.113.20` | every address inside |
| Path | `app.example.com` + `/admin` | requests under that path on that host (web tools) |
| URL | `https://app.example.com/api` | that URL and what is under it |

An exclusion of an asset also matches its other names (a URL on it, its
addresses). An exclusion of an address also excludes the names that resolve
to it, except when the address is a shared front end inside a range a CDN,
edge or hosting provider publishes: then only the address (bare, `host:port`,
URL, inside a range) is left out, and names served through it are still
scanned, port scans on the web ports only. An address known as an edge only
by its network holder's name counts as dedicated. The exclusion preview
lists the names an address exclusion would also stop.

## 3. How an exclusion reaches the sensor

An exclusion is enforced at every hop, so a planning mistake in one place
cannot reach an excluded target.

1. **Dispatch gate** (every path: scheduled, manual and quick scans, workflow
   runs and each workflow hop, automation, coverage, validation and retests,
   connector scans, `POST /commands`). A target an exclusion matches is left
   out of the job. A range target is cut around excluded addresses and the
   rest is sent as pieces (`198.51.100.0/29` minus `.5` becomes
   `198.51.100.0/30`, `198.51.100.4`, `198.51.100.6/31`); it is never dropped
   whole nor scanned through.
2. **The job carries the exclusions.** A job with a range target carries, in
   `payload.exclusions`, the organization's address exclusions near its
   ranges, covered by the job signature. The sensor walks each range address
   by address and leaves out the job's exclusions, its local policy's
   `targets.deny` and the built-in deny list; naabu also gets them as
   `-exclude-hosts`. An exclusion the sensor cannot read refuses the job.
   Older sensors ignore the key; the platform's cut pieces still keep them
   off excluded addresses.
3. **Web jobs carry the deny paths.** A job for a web tool carries
   `web_scope` with the path exclusions of its hosts; the sensor's forwarder
   refuses every request under a deny path, whatever its method, and checks
   redirects again. A rule that blocks only methods other than GET and HEAD
   (Read-only) limits the whole job to GET and HEAD. nuclei, validation and
   retest jobs with a web scope run only on a sensor whose tool network is
   confined (`net.confined@1`, sensor v0.19.0 or later with its seccomp
   profile); without one they wait or are refused with `NO_CONFINED_SENSOR`.
   A web job that cannot carry its scope is not created.
4. **Re-check at claim.** When a sensor picks a job up, its targets pass the
   gate again: an exclusion added while the job was queued takes the target
   out (or fails the job when nothing is left).
5. **Signed jobs.** With job signing, the signer's own ledger holds the
   approved exclusions and refuses to sign a job that names an excluded
   target.
6. **Ingest drops what was not assigned.** A result for an address outside
   the addresses a range job was given (an excluded address included) is
   dropped, never stored.

## 4. What is scanned without an entry

An inventory asset that no scope entry covers, and that nobody excluded or
marked not ours, is **unclassified**. By default (scope setting
`unclassified_scans`, **Low-impact**) it gets low-impact active checks: a
short list of common ports at a low rate, HTTP GET of `/` and
`/.well-known/*`, TLS and tech fingerprinting, nuclei info templates tagged
tech or exposure. Platform guardrails keep it passive instead when its
address is on a CDN, shared-hosting or cloud network, nothing is known about
its network, names of 3 or more registrable domains point at it, or a name
is under none of your domains; a name that resolves only through a wildcard
DNS record is held until someone confirms it (`wildcard_only`); a scan that names it reports the refusal `guardrailed`. Set the setting to **Off** for
passive only, or to **Full** for the scan's own intensity (still
guardrailed). The Strict scan approval mode always means Off.

A port scan of a name reaches only the web ports (80, 443, 8080, 8443) while
an address the name resolves to is not in scope and may not be probed on its
own. Add the address (or your own prefix, offered on the Suggestions tab) to
scope for a full port scan.

Exclusions and "Not ours" always win over all of this.

## 5. CDN, edge and shared-hosting addresses

An address that belongs to a CDN or edge provider (Cloudflare, Fastly, Akamai,
CloudFront and others), a hosting platform or a cloud provider's shared front
end serves many organizations. Scanning it tests the provider's network, not
yours. The platform labels these addresses and leaves the decision to you; it
does not refuse them by itself.

- **Labels:** a name or service served through a provider shows
  **Behind <provider>** in the inventory and the asset drawer. An address in a
  provider's published range shows **<provider> edge** (or *hosting*,
  *shared*), on IP assets and on Scoping > In scope entries. Hover the label
  for the reason.
- **Add to out of scope:** with scope write, click the label on an address.
  A confirm dialog explains why, then adds a *Do not scan* exclusion of that
  address (audited; in the Strict scan approval mode it waits for an
  exclusion approver). From then on no scan, retest or coverage run reaches
  it.
- **Names behind the address:** excluding a shared edge address excludes
  only that address. Names served through it keep being scanned (web ports
  only), because a scan of the name reaches your origin through the
  provider, not the provider's own address. The confirm dialog checks this
  for the address before you confirm. Names that have a dedicated address
  inside an excluded range or CIDR do stop being scanned, and the dialog
  lists how many and a sample.
- **Provider ports:** the ports an IP asset on a provider's edge address
  shows are labelled *Provider ports*: they belong to the provider's
  network, not to your open ports. They stay visible.

## 6. Check what was left out

- **Before a scan starts**: the scan preview lists the targets exclusions
  would leave out, with the matching rule.
- **After it ran**: the run page shows "N targets left out by exclusions",
  each target (a range shows how many addresses it lost) and the rule that
  matched, linked to Scoping > Out of scope.
- **Any target, any time**: the inventory's scope column and the scan
  dialog's check (`POST /scope/check`) say whether a target may be scanned,
  and why not.

## 7. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| The exclusion shows "Pending" | Strict scan approval: exclusions need an approver other than you | Ask an exclusion approver, or decide on Scoping > Approvals |
| A range scan skipped an address you did not exclude | The platform deny list (loopback, metadata, link-local ranges) | Nothing to fix: those are never scanned |
| A port scan of a name found only web ports | An address behind the name is not in scope (section 4) | Add the address or its prefix to scope |
| A name behind a CDN is no longer scanned | Its edge address was added to out of scope (section 5) | Re-include the address, or keep it excluded and accept that the names behind it are not scanned |
| A scan refuses a target as `guardrailed` | A platform guardrail holds it (section 4) | Add its exact scope entry, if it is yours (the refusal offers it) |
