### Fixed: saving risk scoring settings merges partial bodies and refuses unsafe score maps

- `PATCH /settings/risk-scoring` replaced the whole section with the decoded body, so a body that left out `exposure_scores` or `criticality_scores` stored every factor as 0 and every asset scored 0. The body is now merged into the stored settings (omitted fields and blocks keep their stored value), inside the settings write. The score preview reads the body the same way.
- The save refuses all-zero, below-minimum (under 10) and inverted exposure and criticality score maps and returns 400 with the reason; `unknown` exposure and `none` criticality stay outside the ordering. The shipped presets and defaults pass.
- **Upgrade note:** clients that send a full body are unaffected. An organization that already stores an all-zero or inverted map keeps working, and must send valid maps with its next risk-scoring save.
