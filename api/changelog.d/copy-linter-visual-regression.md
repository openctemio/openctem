### Added: copy linter and a visual regression check for the key pages

- Web CI refuses added or changed English strings that use marketing words, "successfully", an exclamation mark, "not just", an em dash aside, a middle-dot separator or a Title Case label (`web/scripts/check-copy.mjs`, also in `make precheck`). `node scripts/check-copy.mjs --all` lists the existing strings to clean up.
- A new workflow takes screenshots of the key pages at desktop and phone width, light and dark, and compares them with committed baselines within 2% (`web-visual.yml`). It runs on the `run-visual` label, nightly on develop and on demand, so pull request CI stays as fast as before.
