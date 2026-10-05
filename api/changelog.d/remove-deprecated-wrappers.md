### Removed: deprecated Go wrappers with no caller

- Internal cleanup, no API change: the ingest handler aliases
  `WorkerFromContext`/`SourceFromContext`, the `config.WorkerConfig` alias,
  `middleware.CORS`, `llm.NewFactoryWithEncryptionLegacy` (it allowed
  plaintext AI keys), the never-set finding notifier, `Evidence.Executor()`,
  and the dashboard service `GetGlobalStats` with its four repository
  queries. Those queries counted rows across every tenant; nothing called
  them, and `/dashboard/stats/global` already uses the per-tenant filtered
  queries.
