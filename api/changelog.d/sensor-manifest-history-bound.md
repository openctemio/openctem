### Security: a sensor cannot grow its stored manifest history without bound

- Every manifest a sensor registers with a new digest is stored as a version, and any unknown member changes the digest. Versions were pruned only beyond the newest 50 and only after 90 days, so a sensor re-registering on every call could store hundreds of thousands of versions a day. A hard cap now keeps at most 100 versions per sensor, whatever their age; the 50-newest and 90-day rule still applies below it.
