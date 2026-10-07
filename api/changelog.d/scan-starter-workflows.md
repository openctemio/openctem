### Added: starter scan workflows (Discover, Discover + Vuln, Web app, Network, Code / CI)

- Five system workflows are built from capability steps, so the platform picks an available tool for each step (migration 001201):
  - **Discover**: subdomains → DNS → HTTP probe;
  - **Discover + Vuln**: adds ports and vulnerability templates;
  - **Web app**: probe → crawl → templates;
  - **Network**: ports → probe → templates;
  - **Code / CI**: secrets, static analysis, dependencies and IaC.
- Each one passes the workflow graph check, and a platform tool resolves for every step. Like every system workflow, they are read-only and copied into an organization on use.
- The new-scan wizard starts with **What to run**: a single check, one of the starter workflows (with its steps), or another of the organization's workflows. This replaces the Single/Workflow switch under Advanced options.
- The presets they replace (Subdomain Enumeration, Port Scanning, Full Reconnaissance, Continuous Monitoring, and the two inactive web and API presets) are deactivated, not deleted. Scans and copies made from them keep working.
- A pipeline step stored without a description no longer fails to load its workflow.
