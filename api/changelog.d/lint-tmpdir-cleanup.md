### Fixed: make lint-new removes its private temp dir on interrupt or kill
- The per-run TMPDIR is now removed by a shell trap, so an interrupted or killed lint run no longer leaves a directory behind.
