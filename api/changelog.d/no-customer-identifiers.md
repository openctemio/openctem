### Security: no customer identifiers in the source tree

- Tests, docs, RFCs and code comments now use documentation names and
  addresses (`example.com`, `example.co.uk`, `example.com.au`, RFC 5737
  addresses, RFC 5398 AS numbers) instead of real customer domains, IP
  addresses and organization names, and the live LAN address.
- Removed: a seed file that only ever targeted one customer tenant (it looked
  that tenant up by name and did nothing otherwise). The `seed` image no
  longer ships it.
- The required **Secret Scanning** check now also fails when a tracked file
  contains a string from the `CUSTOMER_DENYLIST` repository secret
  (newline-separated, case-insensitive fixed strings; the list is never
  committed and the log shows only `file:line`), or the live LAN range
  outside test files. With the secret unset the identifier part is skipped
  with a notice.
