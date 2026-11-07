### Changed: image and contract builds retry the Go module download

- The API image and the OpenAPI contract build retry `go mod download` up to three times, so a reset HTTP/2 stream from the module proxy no longer fails a whole merge group. Checksums are verified as before.
