### Fixed: dashboard first count, plain-word sources and reasons, breadcrumb fold and detail properties

- The dashboard shows one notice while the figures are counted for the first time ("Your figures are being prepared", a few minutes, the page updates by itself) instead of a "No data yet" box per widget.
- Exposure sources read in words in English and Vietnamese (DNS checks, Certificate logs, Paste site, "Data breach: <name>", ...) in the list, the phone cards and the detail header; the detail header names the exposure type in words too.
- Asset change reasons for renames ("Matched by its host ID") and for values decided by a source read in words, with the time in the reader's format.
- The header breadcrumb folds its parent levels into the "…" menu by measured width, so the names that show are whole (tenant app and platform console).
- Detail pages (finding, task, asset): the properties rail is 21rem, and a value that does not fit beside its label goes under it instead of being cut (assignee e-mail, watchers).
- Ready to close: the "how the platform knows" sentence wraps instead of being cut.
- Docs: none (layout and wording of existing pages; web/docs/ui-style-contract.md already states the cut-meaning rule)
