### Changed: the api requires only the sdk-go transfer module

- The api depends on `github.com/openctemio/sdk-go/pkg/transfer` (the chunked feed transfer, its own module tagged `pkg/transfer/vX.Y.Z`) instead of the whole `github.com/openctemio/sdk-go` module, so SDK releases and the SDK's dependency graph no longer reach the api build.
- The dev container builds from the `go.mod` pins with `GOWORK=off`, like CI and the release image: it no longer writes a `go.work` for a mounted `sdk-go` checkout, and such a mount is ignored and can be removed.
