### Changed: RFC-133 and the harness architecture note use generic AI names

- The runtime is the sdk-go `pkg/harness`, the worker repository is `openctemio/ai-worker` and the sensor role is `ai-worker`. The CLI groups are `openctem playbook` (scaffold and test a playbook) and `openctem aiagent` (build, sign and publish an own AI agent). The platform principal is an "AI agent" with a role; the analyst is the first role. RFC-133 and the architecture note are renamed to `RFC-133-ai-harness.md` and `ai-harness.md`.
- RFC-133 gains section 10a, a concept map for AI agents that organizations build themselves, with the controls that are stricter by design.
