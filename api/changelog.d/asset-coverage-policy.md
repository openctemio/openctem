### Added: coverage policy in the asset type registry

- `configs/asset-types.yaml` gains a `coverage:` list per type: the
  capabilities an asset of the type needs, how often (`every`, 1 h to 30 d),
  the stored facts that must hold (`requires`: `resolves`, `web_port`,
  `scope_entry`) and the type a successful run must produce (`expects`).
  First rules: domains (subdomain discovery, DNS, registration, email
  security), subdomains (DNS, dangling DNS, ports, HTTP probe), addresses
  (network owner, ports), open ports (HTTP probe on web ports) and web
  origins (templates). `asset.CoverageRules` reads them.
- The generator validates the rules; a test proves each rule names a stage
  that takes the type and may produce the expected output.
- RFC-093 (asset coverage) is accepted. Nothing schedules work from the
  policy yet.
