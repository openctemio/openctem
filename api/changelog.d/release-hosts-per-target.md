### Changed: a running scan frees each host as soon as it is done with it

- A command used to hold all of its hosts until it ended. Now a host is free for other work of the organization as soon as the command's targets on that host settle. For example, the nuclei tasks for the hosts httpx has already probed start while httpx still works on the rest.
- The sensor names the hosts it freed on its heartbeat (`released_keys`, sdk-go with per-target release). The platform applies them only to commands that sensor holds, and only keys of that command. A re-queued or re-claimed command holds all of its hosts again.
- Older sensors send nothing, so their commands hold their hosts until they end, as before.
- Migration `command_settled_host_keys` adds a nullable column (no rewrite) and replaces `get_next_platform_job` in place.
