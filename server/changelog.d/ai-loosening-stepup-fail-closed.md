### Security: AI settings loosenings never skip the recent sign-in

- Widening automatic AI triage, loosening an AI use case (auto-apply on, a higher data ceiling) and raising the AI autonomy limits ask the signed-in person for a recent re-authentication. A server built without the re-authentication check now refuses these changes (403 `STEP_UP_UNAVAILABLE`) instead of making them without it. Tightening still never prompts.
- Docs: server/docs/architecture/step-up-reauth.md
