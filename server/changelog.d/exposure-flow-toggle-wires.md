### Fixed: dashboard exposure flow wires follow the source rows after the findings/assets switch

- The wires were measured while the ranked rows were still sliding to their new place, so after switching Sources between findings and assets they started at the old row positions and stayed there. They are now measured again once the slide ends, and a row with no layout gets no wire.
