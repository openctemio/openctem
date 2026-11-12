### Added: the signal button variant and the delta and single-measure colour tokens

- `Button` gains `variant="signal"`: a teal fill (the live shape, shadow and hover) for the one main action of a page. No page uses it yet and it is never for destructive acts.
- New theme tokens in light and dark: `--good` and `--bad` for delta meaning (by outcome, not direction), and `--viz-ink` and `--viz-ink-weak` for a chart that shows one measure.
- A single-measure bar and the stat progress fill are neutral ink instead of teal, so teal no longer encodes data. Small chart labels are 12 px.
- The palette check validates the ink colours (4.5:1 on the chart surface) and keeps `theme.css` and `chart-palette.json` in step.
