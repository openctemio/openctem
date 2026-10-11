### Removed: stray test output in the repository root

- `test.txt` and `vet.txt` (local `go test` / `go vet` output committed by mistake) are removed; the root, `api/` and `web/` now ignore loose `*.txt`, `*.out` and `*.log` files.
