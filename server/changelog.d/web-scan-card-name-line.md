### Fixed: scan names keep their line on a phone

- On a 390 px screen the scans list put the last run's state ("Waiting for a sensor") beside the scan name, which left the name about 130 px; a long host name then broke inside a word ("exa|mple.c|om"). The state now sits on the line under the name, and a host name wraps only after its dots and dashes.

Docs: web/docs/ui-style-contract.md (automatic phone card, own cards)
