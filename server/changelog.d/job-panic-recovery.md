### Fixed: a panic in a background job no longer stops the API

- A panic in any background controller, or in one of the background goroutines of the scan scheduler, ingest (sensor statistics, audit writes, contract-mismatch notices) and sensor key use, killed the whole API process, HTTP included; a panic that repeats on the same data crash-looped every replica.
- Each controller run is now recovered: the panic is logged once with the controller name and the stack, counted in `openctem_panics_recovered_total{where="controller:<name>"}` and in the controller's reconcile errors, and the controller runs again on its next tick. The goroutines run through the new `internal/safego` helper, which does the same.
