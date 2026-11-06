### Changed: one remediation group per vulnerable package version

- A package with many advisories was one "Upgrade <package> to <version>" group per advisory (for example about 20 Django groups for one repository, three jQuery groups for the same assets). Every open finding of one installed package version now gets one upgrade target, the highest any of them needs, so the remediation groups list (console and MCP) shows one group that closes them all.
- When a scanner gives the fixed versions only as advice text ("Upgrade Django to 1.11.28, 2.2.10, 3.0.3"), the versions are read from it, so those findings form upgrade groups instead of one group per advice text.
- **Upgrade note:** the remediation key rules move to version 4. The tenant's keys are re-derived before the next suggestion run (no operator action). Open suggestions built on the old groups are replaced by the consolidated ones; findings already in a remediation task stay in it.
