### Removed: five environment variables that switched nothing

- `APP_DEBUG`, `GRPC_PORT`, `LOG_SKIP_HEALTH`, `AI_MAX_CONCURRENT_JOBS` and `AUTH_ALLOW_REGISTRATION` were read (or, for `AUTH_ALLOW_REGISTRATION`, only warned about) but changed no behaviour: no debug mode, no gRPC listener on 9090, health requests are never logged, AI triage runs on the job queue, and sign-up is the console's sign-up policy.
- Startup now **refuses to run** while one of them is set, and the error says what to do instead, the same way it refuses the retired `AGENT_*` names.
- The API image no longer advertises port 9090; it advertises the sensor protocol v3 listener (8443).
- `api/.env.production.example` is removed: nothing referenced it and it drifted from `api/deploy/.env.example`, the production example the Compose stack uses.
- **Upgrade note (one step):** delete these five lines from your `.env`, compose file or chart `extraEnv` before upgrading.
