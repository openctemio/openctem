### Changed: one shared sparkline and delta, and metric tiles can show a change and a trend

- A single `Sparkline` (line or bars) and `Delta` in the UI kit replace three private sparkline implementations and the inline delta markup. Each sparkline is one image named by a text summary for screen readers.
- Metric strip tiles accept a change against the previous period and a small trend under the value.
- Deltas are coloured by outcome (better or worse), using the new `--good` and `--bad` tokens, with the arrow and a spoken verdict so colour is never the only signal. The sensor heartbeat bars use neutral ink.
