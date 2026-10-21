### Fixed: priority classification and threat models see every exposure chain

- Priority classification (the reachability oracle) and threat-model generation read only the 100 best-ranked exposure chains, so assets further down lost the "reachable" boost and a crown-jewel threat model could come out empty. They now read the full result.
- The exposure-chain computation is cached per tenant for 5 minutes and concurrent readers share one run. The page, the MCP tool, the oracle and threat models use the same cache. The 100-row cap applies only to what the API and MCP return, after the caller's data scope. `total_chains` in the response counts all chains the caller may see.
- Priority classification and exposure enrichment share one reachability oracle.
