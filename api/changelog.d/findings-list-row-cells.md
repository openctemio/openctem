### Added: findings list row cells for exploitation, asset facts and duplicates

- The Exploit signals column shows EPSS as a short bar with its percentage on every row (a dash when there is no score), then the KEV and Ransomware chips.
- The Asset cell marks internet-facing assets with a globe and crown jewels with a crown (icons with a tooltip and an accessible name). `GET /findings` rows now carry `asset.is_internet_accessible` (exposure public or reachable from the internet, the product's one rule) and `asset.is_crown_jewel`; the single finding uses the same internet-facing rule.
- A "+2 dup" chip beside the title counts the findings marked as duplicates of this one. `GET /findings` rows carry `duplicates_marked`, compiled as the caller: a duplicate on an asset outside the caller's data scope, in a private program or a pentest campaign they are not in is neither shown nor counted.
- P3 and closed (fixed, false positive, accepted, duplicate) rows and phone cards are dimmed by colour (`--fg-dim`, 4.5:1), never by opacity.
