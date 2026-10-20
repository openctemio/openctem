### Added: Settings > AI and honest AI triage button states

- Organization owners and administrators turn AI triage on or off in Settings > AI (Security group). Turning it on shows what is sent to the AI provider and asks for confirmation; the page shows the provider and the month's token use.
- The AI triage button no longer fails with "You don't have permission" when AI is not available: it explains why (off for the organization, no provider on the installation, monthly allowance used up) and links owners and administrators to Settings > AI.
- Every AI triage text is translated (English and Vietnamese), failures show a message for their code, and a run shows one toast instead of three.

### Fixed: the AI analysis "Confidence" label

- The Overview tab labelled the inverse of the false-positive likelihood as "Confidence". It now shows the false-positive likelihood.
