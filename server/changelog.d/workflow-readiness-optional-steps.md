### Fixed: recon workflows with optional steps are available again

- Subdomains, Web, Standard recon and Deep recon showed "Not available" because their optional steps (takeover check, screenshots, service detection), whose capability no tool implements yet, blocked the whole workflow in the readiness check, although a run already skips such a step with the reason. Readiness now reports an optional step without a tool as `skipped` with its reason, and the workflow stays ready (or waiting for a sensor). Required steps still block.
- Each step's readiness carries a stable reason `code` and the `tools` it names. The workflow list badge opens the steps that need attention and the skipped optional steps, with the reason and the fix link, in English and Vietnamese.
