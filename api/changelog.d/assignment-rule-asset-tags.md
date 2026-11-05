### Fixed: the assignment rule condition "asset tags" checks the asset's tags

- The condition compared the finding's own tags (scanner vocabulary such as `nuclei`, `http`) instead of the tags of the finding's asset, so a rule such as "asset tagged `team:payments`" never fired, or fired on a scanner tag.
- It now matches the asset's tags (case-insensitive, any of the listed tags). The "Test rule" preview uses the same asset lookup. The console labels the condition "Asset tags".
- Rules that already used this condition start matching on asset tags: review them if they were written against scanner tags.
