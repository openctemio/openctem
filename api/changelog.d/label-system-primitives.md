### Added: one label system for every label in the console, first part

- New label primitives in the web console: a machine-health label (icon and plain text), a supporting-fact chip (with a due-date preset), a neutral tag (plain, scoped, colour dot, level), a counter and a feature marker. Severity gains a risk-score form, and the workflow lozenge gains a "waiting" tone.
- Known-exploited and EPSS chips are now presets of the supporting-fact chip; they look and behave as before, and their extra words (past due, ransomware) are separate elements instead of a dotted string.
- User tag colours come from a fixed palette of ten (no teal) and show as a dot beside ink text, so contrast never depends on the chosen colour. Contrast of every new token is tested in light and dark.
- The palette-drift check now refuses, on added lines, colour classes on a badge, text under 12 px on a label, uppercase or mono on a badge, spinning status icons and new ad hoc colour maps.
