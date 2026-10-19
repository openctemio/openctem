### Fixed: the risk scoring preview covers every asset, and recompute writes in batches

- The preview shown before saving risk scoring settings counted only the first 100 assets of the organization (the list page cap ended its loop after one page), so the step-up "apply" decision could rest on a fraction of the inventory. It now reads every live asset by id (keyset paging).
- The finding-priority recompute writes each page's changed findings in one statement instead of one statement per finding. Same rules: a manual class override is kept, closed findings stay frozen, deadlines only tighten. No migration.
