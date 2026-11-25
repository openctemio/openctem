### Fixed: the scan-zone coverage card stays short at any inventory size

- Sensors, Scan zones tab: the Coverage card no longer lists every address outside every zone (one row each, hundreds on a real inventory). It shows labelled counts (private, which scans skip, and public), at most five example addresses (private first) and a link to view all addresses in Assets. The long sentence under the title is gone: the totals stay in the numbers above the zones list.
- The coverage warnings ("Coverage needs attention") no longer stand above the zones list in the API's English: the card says each of them in its own translated words (the counts, the zones without an online sensor, and "Public, any of your sensors scans these (no default zone)"); a warning it does not know is listed at the end of the card.
- The sensors list and the zones list show no pager when every row fits the smallest page (no "Showing 1 to 1 of 1" and "Page 1 of 1" over one sensor or one zone).
- Docs: none (presentation of an existing card; no behaviour, request or API wording changes)
