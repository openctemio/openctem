### Changed: priority and status colours are easier to tell apart in charts

- Priority P0 to P3 is one violet ramp stepped by lightness (at least 0.10 OKLCH between classes, apart under every colour-vision deficiency, 3:1 on every surface); P2 and P3 no longer share a lightness. The priority badge uses the same steps as the charts.
- "Not prioritised" and other "no value" series are drawn as a hatch instead of a borrowed category colour; SLA states in charts use the health colours (breached red, warning amber, on track green).
- Asset criticality charts use a neutral level ramp instead of the severity hues.
- Health icons: ok, warning and down sit apart in lightness, and down and warning no longer match severity Critical and High.
- Part-to-whole dashboard widgets draw one stacked bar with card-coloured separators; stacked areas are solid.
- The contrast test and the palette validator assert lightness steps, colour-vision separation and cross-family distance; the palette gate refuses state text on its own tint and hand-picked hex colours.
