### Changed: the AI worker is described as a separately distributed sensor

- The glossary, RFC-132, RFC-133, RFC-135 and the sensor and AI harness architecture notes no longer link a worker repository. The AI worker is a sensor in the `ai-worker` role that is distributed separately from the core. The open parts are the sdk-go `pkg/harness`, the `ai-worker` sensor role and the job, grant and result contract, so anyone can build a worker against them.
