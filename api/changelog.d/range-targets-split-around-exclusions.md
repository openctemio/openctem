### Behaviour change: a network range is cut around its exclusions instead of being skipped

- A scan or workflow-run target that is an address range (CIDR or `a-b`)
  and overlaps an active address, range or CIDR exclusion used to be skipped
  whole: a /16 with one excluded address was not scanned at all. The target
  gate now subtracts the exclusions and the built-in deny list exactly and
  dispatches the rest as the fewest prefixes that hold it; the excluded
  addresses are never sent. The run's warnings name every cut range and how
  many addresses were left out (RFC-088).
- A range with nothing left is excluded (refused `deny_list` when only the
  deny list removed it). A range target wider than 2^16 addresses is refused
  on every path, including those that skip the scan target validator. More
  than 4 096 pieces in one dispatch is refused with `RANGE_TOO_FRAGMENTED`
  (merge scattered exclusions into wider ones).
- No migration and no operator step.
