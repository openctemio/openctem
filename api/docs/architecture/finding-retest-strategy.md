# Retest strategy by provenance

> How "Retest now" (and proof of fix, and the auto-retest) re-checks a finding
> depends on what raised it. Builds on [continuous retest](continuous-retest.md)
> (RFC-039), [finding retest checks](finding-retest-checks.md) and
> [vulnerability matching](vulnerability-matching.md) (RFC-066). Status:
> shipped (migration 003450).

## Why

A finding raised by the platform's version matcher (tool `version-match`,
source `va`) has its CVE as `rule_id`: there is no scanner rule behind it,
only "this asset runs nginx 1.25.2 and CVE-2023-44487 affects it". Treating
that CVE id as a nuclei template id sent jobs the sensor could only answer
with "the check is not installed on this sensor". The retest now picks how to
re-check from the finding's provenance, checks before dispatch that a sensor
can run it, and says why when nothing can.

## Strategies

`retest.Service.Offer` (and `Request`) classify the finding (`strategyOf`,
`internal/app/retest/strategy.go`):

| Strategy | When | What runs | Settles on |
|---|---|---|---|
| `custom_check` | the finding has a retest check | the check's template, as before | the tool verdict |
| `template` | a scanner rule (nuclei template, or a tool with a retest handler) | that rule, with its own tool | the tool verdict (or the template re-run plus reachability probe on older sensors) |
| `version_recheck` | a `version-match` finding no scanner has reported since | the fingerprint that read the version, as an ad-hoc scan of the asset | the version seen, evaluated against the CVE's affected ranges |
| `none` | a person reported it (manual, pentest, bug bounty, red team, or the manual channel), or a leaked secret | nothing; the retest is refused with a reason | |

A `version-match` finding that a scanner has reported since (its latest
sighting's tool is another tool) is a `template` finding of that scanner.

The list endpoint returns the strategy, the reason a retest would be refused,
and the optional active check:

```json
GET /api/v1/findings/{id}/retests
{"data": [...], "can_retest": true,
 "strategy": {"kind": "version_recheck", "rule": "CVE-2023-44487", "tool": "httpx",
              "product": "nginx", "version": "1.25.2"},
 "active_check": {"template": "CVE-2023-44487", "available": false, "reason": "no_template_sensor"}}
```

`active_check` is present only when a template named after the CVE is known
to be installed (below).

## Version re-check

1. **Eligibility.** The finding's software link (`version_match` metadata:
   product, version, location) joined with `asset_software` gives the source
   that read the version (`SoftwareMatchRepository.FindingLink`). The source
   picks the fingerprint tool: `technology` and an HTTP `Server` header
   (`service` without a port) → `httpx`; a port's `service` or `open_port` →
   `naabu`. `package` and `os` have no network fingerprint: refused with
   `version_source_not_rescannable`. A missing link: `version_evidence_missing`.
2. **Sensor.** An online organization sensor that runs the tool
   (`SensorRepository.FindAvailableWithCapacity` with the tool), else
   `no_sensor` before anything is recorded.
3. **Dispatch.** `scan.Service.QuickScan` with one target (the asset's host,
   with the link's port) and the tool, so every scan target gate applies
   (target validation, act scope, tier ceiling, ownership). The quick scan's
   run is the retest's `run_id`; the retest row records `method = version`
   and gets a two-hour deadline.
4. **Settle.** The sweep skips a version re-check while its scan run is
   pending or running. Once the run ended, the links of the product at the
   location seen since the retest started (`ObservedSince`) decide
   (`DecideVersion`):

   | Seen | Outcome (`reason_code`) |
   |---|---|
   | nothing (after a five-minute wait for the report) | `inconclusive` (`version_not_observed`): a version that is no longer shown is not a fixed one |
   | the finding's own version | `still_vulnerable` (`version_still_affected`) |
   | another version that does not parse | `inconclusive` (`version_not_observed`) |
   | another version still in one of the CVE's ranges | `still_vulnerable` (`version_still_affected`), the new version in the reason |
   | another version outside every range | `confirmed_fixed` (`version_not_affected`) |

   A failed, canceled or blocked run with nothing seen is `inconclusive`
   (`error`). The finding then moves exactly as for any retest (RFC-057 R2 and
   the tenant's auto-resolve setting). The matcher's own reconcile closes the
   finding on a version change as before; the two agree.

## Sensor that has the template

The platform knows each sensor's template release (heartbeat content,
`nuclei-templates`) and the release a finding was found with (template
provenance), not the list of template ids on a sensor. A nuclei template
re-run is addressed to one sensor (`commands.sensor_id` before the claim)
picked by `PickTemplateSensor`:

1. the sensor that last reported the finding (it ran the template), if it is
   online with the retest capability;
2. else the sensor with the newest release at or above the finding's release;
3. else a sensor that reports no release;
4. else, every online sensor reports an older release: refused with
   `no_template_sensor` (API code `RETEST_NO_TEMPLATE_SENSOR`).

**Active check.** For a version-match finding, a template named after the CVE
is offered as an optional active check only when a nuclei finding of that
rule was reported by a sensor of the same organization
(`FindingRepository.TemplateSightingSensors`); the check is addressed to that
sensor while it is online. It is never required: the version re-check stays
the default. `POST /api/v1/findings/{id}/retests` with `{"mode": "active_check"}`
runs it; other findings get 400.

**Re-verify.** `POST /api/v1/findings/{id}/validate` sends a cross-scanner
finding's CVE as a template candidate only on the same evidence; otherwise it
runs the reachability check.

## Errors

A refused retest returns a registered code with the retest reason in
`details.reason` (422): `RETEST_NOT_AVAILABLE` (ineligible; the reason says
why), `RETEST_NO_SENSOR`, `RETEST_NO_CHECK_SENSOR`, `RETEST_NO_TEMPLATE_SENSOR`.
A target the scan policy refuses keeps its 400 with the policy text.

## Console

The retest panel (`web/src/features/findings/components/detail/finding-retest.tsx`)
reads the strategy: "Re-check version" with a tooltip naming the tool, the
product and the CVE; "Retest now" with "Run the check <template>"; an
"Active check" button when one is available. An open finding that cannot be
retested shows a disabled button and the reason (pentest findings keep their
tester retests). Strings are in `findings.retestPanel.*`,
`findings.verification.reason.*` and `errors.RETEST_*` (en, vi).

## Security

- Tenant isolation: every read is tenant-scoped (`FindingLink`,
  `ObservedSince`, `TemplateSightingSensors` filter on the tenant; the
  software corpus ranges are global, public data). A finding id of another
  tenant is "not found". Sensors picked for a command come from the tenant's
  own organization sensors only (`FindAvailableWithCapacity`), never a shared
  instance sensor.
- Authorization is unchanged: `findings:verify` on the retest route, the data
  scope guard on the finding.
- Probing: the fingerprint is an ordinary quick scan through every scan gate;
  the active check passes the template guard and the active-probe gate like
  any retest. A refused target never records a retest.
- No template content or id is guessed: a CVE id reaches a sensor as a
  template only when that template already ran on one of the organization's
  sensors.

## Key files

`internal/app/retest/strategy.go`, `version.go`, `service.go`;
`internal/infra/postgres/softwarematch_repository.go` (`FindingLink`,
`ObservedSince`), `finding_template_sightings.go`,
`finding_retest_repository.go`; `internal/app/validation/run.go`
(`signatureInstalled`), `retest_command.go` (`SensorID`);
`cmd/server/services.go` (`retestFingerprinter`, sensor candidates);
migration `003450_retest_version_recheck`. Tests: `internal/app/retest/strategy_test.go`,
`provenance_test.go`, `internal/infra/postgres/retest_version_evidence_db_test.go`,
`internal/infra/http/handler/finding_retest_errors_test.go`,
`internal/app/validation/nuclei_routing_test.go`, web
`finding-retest.test.tsx`.

## How a scan decides which nuclei templates it runs

For reference (retests use the same sensors and template sets):

1. **Installed set.** The `nuclei-templates` release on the sensor that claims
   the job. The sensor host keeps and refreshes it; the organization's content
   policy can pin a release or cap its age (RFC-031), and the release shows
   on the sensor page and in each finding's template provenance. The platform
   never names a template source. The organization's custom templates travel
   inside the job.
2. **Scan settings** narrow it: `tags`, `severity` and `exclude_tags` of the
   scan profile or workflow step (`exclude_tags` only adds to the sensor's own
   exclusions), and the scan's intensity ceiling.
3. **Fixed exclusions** on every scan (`-etags` on the command line, sensor
   side): `intrusive`, `default-login`, `dos`, `fuzz`, `fuzzing`, `bruteforce`,
   `brute-force`, plus the release's own default ignore list. A scan cannot
   select those tags, and flags that would re-admit them are refused.
4. **Re-checks** (retest, re-verify) run one template by id with `dos`,
   `fuzz`, `intrusive`, `brute-force`, `bruteforce`, `default-login` excluded,
   and discard a result from a template that turns out to be of such a class.
