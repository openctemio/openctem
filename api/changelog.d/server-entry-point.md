### Changed: the server's code moved to api/internal/server; api/pkg/server.Main is the public entry point
- The server's code moved from `api/cmd/server` to `api/internal/server`. `api/cmd/server/main.go` is now one line that calls `server.Main()` from the new public package `api/pkg/server`, which a custom build in a separate Go module can import and call from its own `main`.
- The server's command-line flags are defined on a flag set created inside `Main`, so importing the package adds nothing to the importer's global flags. The binary's behaviour, flags and tool dispatch are unchanged.
