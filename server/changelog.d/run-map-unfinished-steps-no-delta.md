### Fixed: a failed run no longer shows the last run's assets as gone

- The run view compared every step's outputs with the previous completed run of the scan. A step that did no work (no sensor picked it up, it failed or timed out) produced no asset, so the view showed "Compared with the last run: 9 gone" for every asset of the last run, although nothing disappeared. The comparison was display only: no asset state changed. `GET /scan-runs/{id}/map` now compares only steps that finished their work (completed or partial); the others carry no `previous`, `added` or `gone`.
