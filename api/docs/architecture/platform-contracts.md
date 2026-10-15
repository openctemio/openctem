# Platform contracts

Design: [RFC-094](../rfcs/RFC-094-platform-contracts-only.md).

The platform (`api/`, `web/`) depends on contracts, never on a sensor
implementation or on the sensor SDK. Every sensor product (the scanning
sensor, the Tenable.sc connector, inventory collectors, sensors that
customers build on sdk-go) is handled by the same code.

| the platform may depend on | where |
|---|---|
| ctis: schemas, importers, `capability`, `settings`, `tooloption`, `politeness`, `source`, `outcome`, `fingerprint` | `github.com/openctemio/ctis` |
| ctis feed transfer (bundle format, fetcher) | `github.com/openctemio/ctis/transfer` (its own module) |
| the sensor protocol (versioned) | `api/pkg/sensorproto` |
| what a sensor reports under its signed key: manifest, tool descriptors, config report, checks | stored per sensor |
| catalog data: sensor products and their release lines | `versions.yaml` |

## Shipped

- The api requires no `github.com/openctemio/sdk-go` module:
  `GOWORK=off go mod why -m github.com/openctemio/sdk-go` answers
  "main module does not need module".
- CI job **Platform depends on contracts only** (workflow
  `repo-security.yml`, script `.github/scripts/check-platform-deps.sh` with
  its self-test) fails on a require, replace or `go.sum` line, a Go import,
  an npm dependency or a web import of the sensor SDK, a sensor or a
  connector product.

## Planned

Port-scan caps and retest by capability, install snippets per product,
check fix data reported by the sensor, and the move of the sensor and SDK
lint rules out of this repository: RFC-094 §6.

## Adding shared code

Code that both the platform and a sensor need is a contract: add it to ctis
(a new package, or its own module when it needs a dependency), release it,
and import it from both sides. Never import it from sdk-go into the
platform.
