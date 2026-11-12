### Removed: the six inert AI triage sub-modules

- The sub-modules `ai_triage.bulk`, `ai_triage.auto`, `ai_triage.workflow`, `ai_triage.byok`, `ai_triage.agent` and `ai_triage.custom_prompts` are removed. Nothing ever checked them: AI triage is gated by the `ai_triage` module and the `ai_triage:*` permissions, so switching a sub-module off did nothing.
- Migration `20261028153739_retire_ai_triage_submodules` moves any permission or event type filed under them to `ai_triage` and deletes the sub-module rows and the per-tenant toggles of those sub-modules (they had no effect). Its down restores the six rows but not the toggles.
- The `ai_triage` module description no longer lists modes.
- A test now guards that AI triage never writes a finding's severity or priority: model output stays a suggestion on the triage result until a person acts on it.
