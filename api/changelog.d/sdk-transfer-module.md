### Changed: the api depends on no sensor SDK module

- The chunked feed transfer (fetcher, bundle format, writer and consumer) comes from the contract module `github.com/openctemio/ctis/transfer`, where it moved unchanged from `github.com/openctemio/sdk-go/pkg/transfer` v0.1.0; bundles are byte-identical. The api no longer requires any `github.com/openctemio/sdk-go` module, so SDK releases and the SDK dependency graph never reach the api build (RFC-094).
- CI job "Platform depends on contracts only" fails when `api/` or `web/` requires, imports or vendors the sensor SDK or a sensor.
- The dev container builds from the `go.mod` pins with `GOWORK=off`, like CI and the release image: it no longer writes a `go.work` for a mounted `sdk-go` checkout, and such a mount is ignored and can be removed.
