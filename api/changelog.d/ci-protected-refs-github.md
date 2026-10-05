### Security: GitHub CI trust can require protected refs through deployment environments

- A CI trust configuration's **Protected branches and tags only** switch now works on GitHub: GitHub tokens carry no protected-ref claim, so the job must run in one of the configuration's listed deployment environments (whose deployment branch rules admit only protected refs). Before, a GitHub configuration with the switch silently admitted nothing.
- Saving a GitHub configuration with the switch and no environments is refused with a validation error.
- New tests pin the run token's least privilege over the real route registration (a run token reaches no tenant, console, API-key or MCP route; run routes accept no other credential) and the workload token's one-minute clock-skew bound.
