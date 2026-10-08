### Fixed: system workflow templates no longer pin tools that may be missing

- The older system templates (Subdomain Enumeration, Port Scanning, Full
  Reconnaissance, Web Vulnerability Scan, API Security Testing, Continuous
  Monitoring) now use capability steps with "Any tool", like the starter
  templates: each step names its capability and the platform picks an
  available tool. A copy made from one used to fail to save on an
  organization without one of the pinned tools.
- Steps no catalog capability runs (dalfox, sqlmap, kiterunner, ffuf, report
  and rate-limit steps) are removed; the steps that waited for them no longer
  do. Settings keep only the capability's standard params (`top_ports: "1000"`
  becomes `top_n: 1000`).
- Only system templates change (migration 001322). Organizations' own copies
  are untouched. The down migration restores the previous steps.
