### Added: two sensors never scan the same host at once for workflow steps

- Now that a workflow step is shared between sensors, the platform keeps them off the same host at the same time. A chunk of an active step (port scan, HTTP probe, crawl, vulnerability templates) records the hosts it hits. While one sensor runs that chunk, no other chunk of the organization that touches one of those hosts is offered or can be claimed, and two sensors claiming at the same moment are serialized.
- A host is free again as soon as the chunk finishes, fails or is released, or its lease runs out. Passive steps (subdomain discovery, DNS resolution) are not limited. Another organization's work never holds yours back.
- Migration `001168_command_host_keys` adds `commands.host_keys` and a partial index. Each sensor's own per-host limit stays as a second line of defense.
