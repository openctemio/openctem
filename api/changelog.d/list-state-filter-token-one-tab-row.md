### Changed: one tab row per page; a list's status or kind is a filter in its toolbar

- Approvals, Assets › Activity, Remediation tasks and campaigns, Attack surface › Web surface and Scope no longer show a second row of tabs or a segmented control under the page tabs. The status or kind of the rows is a filter token at the start of the list toolbar ("Status: Pending"), with a count per value in its menu and its value in the URL, so a filtered list can be linked.
- CI/CD shows one tab row: Pipelines, Runs, Coverage, Trust and gate.
- Exposures and Exposures › Vulnerabilities switch between the list and the analytics or summary with a view switch in the page header. On Vulnerabilities, a "CVEs" filter picks the CVEs affecting your assets or the whole catalog.
- Scope › Domain proof and Scope › Networks are their own tabs of the Scope section (`/scope/domain-proof`, `/scope/networks`), with the same permission and module as before.
- Components drops the preset row that repeated its strip tiles; the Packages tile clears the presets. The Exposures strip drops its mean-time tile, which opened no list.
- The Activity period moved from the page header into the list toolbar. The Activity, Web surface and Approvals toolbars stay in place while their list loads or fails.
- Assets › Inventory follows the shared page spacing.
