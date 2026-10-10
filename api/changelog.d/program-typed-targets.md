### Security: a program target limited to a port or a path never authorizes the whole host

- Pasted, imported and feed program targets such as `api.example.com:8443/tcp`, `10.0.0.5:22` or `https://api.example.com:8443` used to become entries for the whole host (the port was dropped). They now become entries limited to that port (`scope_targets.ports`, `protocol`, migration `001910`); a bare host, another port or a full port scan is not covered.
- A URL entry with a path covers only URLs under the path, segment by segment, and refuses dot segments (`/api/../admin`, `%2e%2e`).
- A target only limited entries cover goes only to tools that stay on the target they are given (`naabu` with a port list inside the limit, `httpx`); crawlers, template scanners and `top_ports` are refused there (refusal `constrained`) at claim and by the job signer, whose ledger now carries the limit (relaxing it is a widening).
- **Upgrade note:** none. Existing entries have no limit and behave as before; feed bundles with schema 1.1 `ports` (strings) and `requires` (string) are now read.

### Added: per-target program qualifiers

- Program targets keep and show what the program says about each: bounty eligibility, maximum severity, environment, testing instructions, prerequisites and trust (published, listed by the platform, inferred). They never authorize anything.
