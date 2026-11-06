### Fixed: grouped list headers no longer overflow their row

- In grouped lists (Findings grouped by CVE, asset, owner, severity, source, component, type or family, the fixes awaiting verification queue, and leaked credentials grouped by identity), a group header with a status summary and actions ran past the table on narrower screens or with the filter panel open: the name was squeezed out, Approve and Reject sat over the Source and Location columns and under the row-actions column, and the table scrolled sideways.
- The header is now one wrapping line of three slots (name and facts, status summary, actions). When it does not fit, the summary and then the actions move to the next line; the actions never shrink or overlap.
