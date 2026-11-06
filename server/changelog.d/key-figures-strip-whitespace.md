### Fixed: key figures widget without the extra whitespace
  - The Key figures strip on dashboards no longer leaves a blank band under its tiles when the stored layout gave it more than one row: it is now always as tall as its tiles.
  - The strip sits flush in its widget frame: its first figure lines up with the title and the tiles are shorter, instead of padding on top of padding. `MetricStrip` gets an `embedded` variant for this, replacing a one-off class override.
