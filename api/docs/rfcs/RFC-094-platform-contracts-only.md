# RFC-094: The platform depends on contracts only

| | |
|---|---|
| Status | Proposed (2026-10-14). Implemented: the api requires no sensor SDK module (feed transfer from `ctis/transfer`) and CI refuses a sensor or SDK dependency in `api/` or `web/`. In implementation: port-scan caps and retest by capability, the sensor product catalog. Designed: the remaining steps |
| Scope | api, web, ctis (`transfer`, contract packages), sdk-go (removes its `pkg/transfer`), versions.yaml (sensor product catalog) |
| Related | RFC-092 (tool-agnostic platform), RFC-055 (tool contract), RFC-033 (sensor manifest), RFC-037 (versions.yaml), RFC-072 (feed transfer, D1 amended), RFC-040 (mutual distrust) |

## 1. Summary

Many sensors talk to one platform: the scanning sensor, the Tenable.sc
connector, inventory collectors and the sensors customers build on sdk-go.
The platform must treat every one of them the same, so it may depend only on
**contracts**:

- **ctis**: report schemas, importers and the contract packages (`capability`,
  `settings`, `tooloption`, `politeness`, `source`, `outcome`, `fingerprint`,
  `transfer`);
- the **sensor protocol** (versioned, `pkg/sensorproto` in the api);
- the **signed manifest** and the reports a sensor sends under it (tool
  descriptors, config report, preflight checks);
- **catalog data** in `versions.yaml` (the sensor product catalog).

It never compiles in, imports or hard-codes the behaviour of one sensor
implementation or of the SDK.

## 2. Invariants

| # | invariant | how it is held |
|---|---|---|
| I1 | The platform compiles and its tests pass with no sdk-go or sensor module in reach: `go mod why -m github.com/openctemio/sdk-go` reports that the main module does not need it | CI job "Platform depends on contracts only" (`.github/scripts/check-platform-deps.sh`): no require, replace or `go.sum` line, no import, no npm dependency; it has a self-test |
| I2 | A new sensor product or a new version of one needs no platform change | product facts (image, release channel, install templates, docs) are catalog data; behaviour facts (tools, settings, checks, features) come from what the sensor reports |
| I3 | A sensor is accepted or refused by protocol version and capabilities only | the SDK version is informational; known-vulnerable SDK versions are an optional advisory list in the catalog, never a gate |
| I4 | Behaviour is keyed by capability, never by a tool name | RFC-092; the port-scan cap and validation/retest are the first two moved |
| I5 | Text a sensor reports is data: bounded, stripped of control characters, rendered as text | existing manifest sanitisation (RFC-092 §3.7) applies to every new reported field |

## 3. What is where today

An inventory of api and web (2026-10-14, develop `7e8a6d7ed`) found:

| class | api | web | target |
|---|---|---|---|
| module dependency on sdk-go (feed transfer) | 13 files | 0 | ctis `transfer` (done) |
| one release channel for every sensor (`sensor.latest/min`, `sdk.latest/min`, image repository, install tag) | 14 sites | 8 | catalog per product |
| SDK version used as a gate (`MinSDKForProgramHTTPRules`) | 1 | 0 | a manifest feature (`http_policy`) |
| install snippets: the scanning sensor's env names, paths, flags, seccomp file names, Helm keys (`configs/sensor-templates`) | ~30 sites, 16 templates | 12 | per-product templates in the catalog, rendered from data |
| config-check fix texts naming one sensor's env, image and flags | 20 ids / 50 entries | 0 | fixes reported by the sensor (keys, values and formats); wording stays platform-owned |
| hard-coded sensor tool lists (trust list, retired names, defaults) | 9 | 1 (dead) | RFC-092 P1 |
| tool-specific branches | 117 (RFC-092 §1) | | RFC-092 P1/P2 |
| sensor kinds in grant profiles and UI | 15 | 12 | profiles stay platform policy; display from data |
| CI checks out the sensor and sdk-go repositories (`security-lint.sh` rules 1, 4, 5, 6) | 1 workflow | | rules move to those repositories; the shared SSRF table becomes a ctis contract |

The full file-by-file inventory is kept with the design notes; this RFC
records the classes and the decisions.

## 4. Design

### 4.1 Contracts move into ctis

A package the platform needs from the SDK is a contract, so it moves into
ctis and both sides import it from there. `transfer` (RFC-072) was the only
one: it moved unchanged into its own module `github.com/openctemio/ctis/transfer`
(the ctis root module keeps zero external dependencies), pinned by a golden
test to the v0.1.0 bytes. sdk-go drops its copy; the feed publishers switch
the import path.

### 4.2 Sensor product catalog (catalog data)

`versions.yaml` holds one section per sensor product (built by the sensor
product catalog work, package `internal/versions`): the product id the sensor
reports in its signed manifest, image repository, latest and minimum release,
install snippet set and release identity. Health and "update available" use
the release line of the sensor's own product; a sensor of a product the
catalog does not list gets version status `unknown`, never `degraded` (it is
not judged against another product's releases). The console names products
by product id through i18n keys. A new product, ours or a customer's, is a
new section: no Go change.

### 4.3 Install snippets are product data

The install snippets (docker, compose, kubernetes, helm, env, yaml, cli,
policy) are templates of a product, not platform code. They move from
`configs/sensor-templates/` to the product's directory in the catalog; the
platform renders the template of the sensor's product with the same closed
data (API URL, key reference, image and tag from the catalog, CA, name) and
never names an env variable itself. A product without templates shows the
generic pairing instructions only. Customer products add a directory and a
catalog entry; no Go change.

### 4.4 Checks: the sensor reports facts, the platform owns the words

Config and preflight checks keep platform-owned wording (a hostile sensor
must not phish through check text, RFC-040). The parts that name one
sensor's configuration (the env name, Helm key, CLI flag, path, image) are
**reported** by the sensor with the check, as structured fix data
(`{format: env|compose|helm|cli, key, value}`, closed formats, bounded, keys
matching `^[A-Za-z_][A-Za-z0-9_.-]{0,63}$`), and the platform renders them in
its own sentence. The settings registry the sensor already reports
(sdk-go `settingsreg`, the config report's settings table) is the source of
names and defaults.

### 4.5 Compatibility

A sensor is accepted when its protocol version is one the platform speaks,
and it is given only work its reported capabilities and features cover;
nothing else. The SDK name and version are stored and shown. The catalog's
optional `sdk.advisories` lists SDK versions with a known vulnerability; a
matching sensor shows status `advisory` with a warning, never a refusal and
never a held job. The one SDK version gate today (program HTTP rules held
from sensors below SDK v0.19.0) becomes a protocol feature the sensor reports.

### 4.6 Capability, not tool

Two safety behaviours are keyed by a tool name and move first:

- the port-scan caps of active EASM jobs (`easm/active_gate.go`) apply to any
  job whose capability is `scan.ports`, whatever tool runs it; a tool that
  only resolves the capability from its contract is no longer exempt;
- validation and retest are routed by capability `verify.finding`, offered by
  any sensor whose tools declare it; the nuclei path becomes one
  implementation.

The rest follows RFC-092 P1/P2.

## 5. Security

| threat | control |
|---|---|
| a sensor or SDK change reaches the platform build | I1 CI guard; contracts in ctis are versioned and reviewed on their own |
| a port scanner other than the expected tool bypasses the per-job port cap | the cap is keyed by capability (§4.6), with tests for an unnamed tool |
| a hostile sensor reports fix data to steer an operator into a dangerous command | closed formats and key pattern; the platform owns the sentence; values are shown as text, never executed |
| a product entry or template is edited to point at another image | the catalog is repository data reviewed like code; templates render only closed fields |
| a sensor claims an old SDK to dodge an advisory | advisories never gate, so there is nothing to dodge; gates are protocol and capabilities, which the platform checks itself |

Tenant isolation is unchanged: nothing here adds a tenant-scoped query; the
catalog is global, read-only data.

## 6. Plan

| step | repo | content | state |
|---|---|---|---|
| 1 | ctis | `transfer` module with golden bytes | PR open |
| 2 | sdk-go | remove `pkg/transfer` | after 1 |
| 3 | api | require `ctis/transfer`; CI guard | this RFC's first PR |
| 4 | api | port-scan cap by capability | in implementation |
| 5 | api, web | retest / validation by capability | in implementation |
| 6 | api | product catalog, SDK advisories, no SDK floor | sensor product catalog work |
| 6b | api, sdk-go | program HTTP rules gated by a reported protocol feature, not the SDK version | designed |
| 7 | api, web | install templates per product | designed, needs the catalog |
| 8 | api, sdk-go, sensor | reported fix data for checks | designed (protocol addition) |
| 9 | ci | security-lint rules for sensor and SDK code move to their repositories; SSRF table into ctis | designed |

## 7. Decisions

| # | question | recommendation |
|---|---|---|
| D1 | Unknown product: version judgement? | none (`unknown`); show the reported version only |
| D2 | Program HTTP rules on a sensor without the feature | hold the job (as today for old SDKs) |
| D3 | Reported fix data: new protocol field or a new config-report version | additive field in the config report; old sensors keep the platform's generic text |
