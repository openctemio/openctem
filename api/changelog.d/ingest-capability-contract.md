### Added: ingest accepts CTIS 1.5 and binds sensor reports to their capability

- **CTIS 1.5.** The API reads CTIS 1.5 reports (ctis `main`): `metadata.capability`, `asset.technologies`, `relationships` and `finding.attack`. This is the receiver-first step, so sensors can send them later. Reports of 1.0 to 1.4 are unchanged.
- **Tool contracts.** A tool contract in the sensor manifest keeps:
  - `implements`, the capability references of the tool's descriptor (`scan.ports@1`), matched exactly against the ctis taxonomy;
  - `batch`;
  - `origin` (`builtin` or `adapter`).
- **Capability of a command-bound report.** The platform derives it from the command's tool: its catalog stages, plus the capabilities it declares in its sensor's manifest (tenant-scoped).
  - The sensor's `metadata.capability` is kept only when it names one of those candidates.
  - A report that is not bound to a command has no capability.
- **Port-closure reconciliation** (a port missing from the next scan is closed) now applies to any report bound to `scan.ports`, not only to tools on a name list.
- **Finding source by capability.** The detection technique of a bound report (SAST, secret, SCA, container, IaC, DAST, EASM, VA, CSPM) comes from its capability, so a third-party tool needs no entry in the tool-name table. Unbound reports keep the name rules. A report bound to `secrets.code` is masked as a secret scan whatever its tool is called.
- **Required output.** A report that misses the required output of its capability is logged and counted (`capability_contract_warned`) and applied as before. This is warn first, per decision TC13 of RFC-055.

### Security: a report's capability comes from the platform, never from the sensor alone

- The capability that drives capability-specific handling is never taken from the sensor alone, and never from another tenant's manifest.
- A tool contract whose `implements` names an unknown capability, a reference without its major, or a look-alike is dropped whole, as any invalid contract is.
- An unknown `origin` drops the contract too.
