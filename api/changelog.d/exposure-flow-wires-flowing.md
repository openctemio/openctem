### Fixed: every Exposure flow source has its wire, carrying findings

- Grouped by sensor or instance, the Exposure flow card now draws a wire from every shown source row to the rings, as it already did grouped by tool. A source that sent no findings gets a thin dashed still wire instead of none.
- A wire always carries the findings a source sent, also when the sources are ranked by assets, in the Exposure flow and in the Intake panel. Ranked by assets, a line under the switchers says that assets are not findings and that the lines carry findings only.

### Changed: Exposure flow and Intake wires flow with their volume

- The travelling light on a healthy wire now runs faster for more findings received (log scale, 3.2 s to 1.1 s per cycle); none for a wire with nothing received.
- The lights pause while the card is off screen or the browser tab is hidden, and are not drawn at all when the system asks for reduced motion. Width and figures carry the same numbers.
