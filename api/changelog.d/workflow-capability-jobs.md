### Added: workflow steps run as capability jobs

- A workflow step whose tool runs capability jobs on the sensor (subfinder, dnsx, naabu, httpx, katana, nuclei, trivy, semgrep, codeql, betterleaks) now names its capability in the command (`capability`, for example `scan.ports@1`). The sensor then checks:
  - that the tool implements the capability;
  - the tool's output against the capability's contract.

  It also records the capability in the result's provenance (RFC-055).
- The step's settings stay in `config`, mapped to the tool's keys as before, so a sensor older than the tool contract runs the step unchanged. Commands for other tools are unchanged.
