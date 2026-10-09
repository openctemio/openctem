### Security: accepting a quarantined sensor report keeps the protocol v2 protections

- Parts of a protocol v2 report that a tool does not produce are held for review. They were stored labelled as protocol v1. Accepting such an item, or one stored by protocol v1, skipped two v2 protections:
  - A finding without an asset could get an asset invented from the report's metadata.
  - The shared CVE catalog could be written from sensor data.
- Every accepted item now keeps both protections, and held parts are labelled v2.
