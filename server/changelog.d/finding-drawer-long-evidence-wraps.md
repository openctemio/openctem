### Fixed: long evidence stays inside the finding detail drawer

- A finding whose evidence held a long unbroken value (an extracted JSON string with escaped slashes, a long path or digest) made the drawer scroll sideways and pushed the evidence, the matched line, the template line and the due date out of view. Such values now wrap inside their evidence item, and the header's address line wraps too. Raw request and response blocks still scroll inside their own box. The full finding page shares these components.
