### Added: scan workflow connections say what they carry

- In the scan workflow builder, every connection between two steps is labelled with the data types that pass along it (for example `url · ip`, or `url · service +2` when more types pass), worked out by the same rule the save check applies. A connection that only orders two steps reads "order only", and one that cannot pass data reads "no matching type" or "not fed: intrusive", drawn in the error colour.
- Each connection's accessible name is a full sentence ("HTTP probe passes URL, IP address to Vulnerability templates"), shown as a tooltip too; labels hide below half zoom. The read-only graph of a workflow shows the same labels.
- Connections are no longer animated, and the builder's line colours follow the light and dark theme.
