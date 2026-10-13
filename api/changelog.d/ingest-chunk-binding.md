### Security: results outside a scan chunk's addresses are dropped

- A scan command whose targets are all addresses, ranges or services on addresses can only observe those addresses. At ingest, a report asset of such a command that names only other addresses (its own name, the host of a service or URL, or listed addresses) is now dropped with its findings and counted in `assets_outside_chunk` (RFC-088 output binding). A compromised or buggy sensor can no longer add assets outside the chunk it was given.
- Commands that name a host name, retests, validations and trusted uploads are not affected; an asset that names no address is left to the other checks.
