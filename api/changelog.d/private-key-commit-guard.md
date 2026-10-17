### Changed: a committed private key is now blocked in CI and by the pre-commit hook

- The Secret Scanning job fails a change that adds a private key block, a key or keystore file, or anything under `data/`; the pre-commit hook runs the same check. Throwaway keys under `testdata/` are allowed.
- `SENSOR_MTLS_CA_DIR` documents that a relative default resolves against the working directory, so run from a source checkout with it pointed outside the checkout.
