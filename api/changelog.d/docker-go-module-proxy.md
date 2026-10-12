### Security: image builds verify openctemio modules against the Go checksum database

- The API and admin-cli images no longer set `GOPRIVATE=github.com/openctemio/*`.
  The modules are public, so they now come through the Go module proxy and are
  checked against the checksum database like every other dependency. This also
  ends flaky builds where a pre-release ctis version had to be fetched from git
  directly ("shallow file has changed since we read it").
