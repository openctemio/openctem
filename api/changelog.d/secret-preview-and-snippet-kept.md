### Fixed: a secret finding keeps its masked code line and the producer's preview

- The value of a secret finding no longer reads `RE…ED`: a preview made by the producer (for example `AKIA…MPLE`) is kept as sent, and a value that hides everything (`REDACTED`, only mask characters) has no preview. A later scan replaces an empty or `RE…ED` preview.
- The stored snippet is the producer's masked source line instead of the preview. A snippet that still holds a secret-looking word is replaced by `[redacted secret]` and its context lines are dropped.

### Security: code lines of secret findings no longer go to the AI provider or into exports

- AI triage prompts and finding exports (NDJSON) leave out the snippet and context lines of a secret finding. File, line and preview are still sent.
