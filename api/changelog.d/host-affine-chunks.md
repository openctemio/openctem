### Changed: a step's chunks never wait for each other

- A step cut into chunks puts every target of one host in one chunk: a name with its URLs and services, an address with its `address:port` forms, a range with the addresses of its buckets, and a name with the addresses the inventory says it resolves to. Two chunks of one step no longer hold the same host, so one chunk never waits for its sibling while a sensor slot is free.
- The chunks of a step are evenly filled: 450 targets with a chunk size of 200 are three chunks of 150, not 200, 200 and 50. The number of chunks is unchanged.
- A host with more targets than a chunk holds gets chunks of its own, which run one after the other.
