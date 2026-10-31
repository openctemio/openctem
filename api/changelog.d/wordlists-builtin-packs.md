### Added: subdomain enumeration works on a fresh install

- The curated wordlist packs of the current release (`wordlists-s`, `wordlists-m`, 2026.10.1) are built into the API and installed on start when the platform has no stable wordlist pack, so asset coverage no longer waits on an import (`content_missing`). An existing stable channel is never moved.
- The list generated for each enumeration job now adds permutations of the organization's own labels: numbered neighbors (`web09` → `web10`), numbered environment names (`charts-uat` → `charts-uat2`) and base words crossed with the environment words the organization uses.
- The wordlist release workflow checks the published assets are byte for byte the built-in packs.
