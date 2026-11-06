### Added: add a pasted list of names to scope in one go

- The Add to scope dialog accepts a list: one value per line, or separated by commas or spaces, so a spreadsheet column can be pasted. Each value's kind is detected, repeats are counted once, values that are not recognised can be removed, and the Covers choice, duration and probe depth apply to the whole list. Lists of up to 1,000 values are sent in batches of 200 with one step-up, and the result shows what was added, what was already in scope and what was refused, with the reason.
- `POST /scope/targets/bulk` takes optional `expires_in_days` and `max_tier`, applied to every item under the same rules as `POST /scope/targets`. Omitted, the entries stay permanent at the organization's default tier, as before.
