# Third-party data: can-i-take-over-xyz fingerprints

`can-i-take-over-xyz.json` is the `fingerprints.json` file of
**can-i-take-over-xyz** by EdOverflow and contributors,
<https://github.com/EdOverflow/can-i-take-over-xyz>, copied unmodified from
commit `5bd4e12837911c8475486f1da922c9b9c706e632` (2025-02-08).

It is licensed under the **Creative Commons Attribution 4.0 International**
license (CC BY 4.0), <https://creativecommons.org/licenses/by/4.0/>. The Free
Software Foundation lists CC BY 4.0 as compatible with the GNU GPL version 3,
which OpenCTEM is released under.

OpenCTEM reads only the `service`, `cname`, `status` and `nxdomain` fields, to
decide whether a CNAME that points at a non-existent target belongs to a
provider where anyone can claim that name. It never fetches the candidate over
HTTP (that confirmation is a sensor check), so the HTTP `fingerprint` strings
are unused.

To update: replace the file with a newer `fingerprints.json`, update the
commit and date above, and run `go test ./internal/app/easmdns/...` (the
loader test pins the structure).
