### Fixed: New Scan target limits, all asset groups, tier-aware scope preview

- New Scan no longer drops targets past the first 1,000 without a word: the Targets step says how many are selected and what to do. Validation errors now show their reason (for example "targets must be at most 1000 items") instead of "Validation failed".
- Every asset group can be picked: the list loads 100 groups by name with a search box (it showed only the first 20).
- Selected assets keep their names after going back to the Targets step.
- The live scope preview of a single check and of a quick scan checks at the scanner tier, so an intrusive scanner shows the targets the scan would refuse. `POST /api/v1/scope/check` accepts `scanner_name` for this.
