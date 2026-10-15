### Changed: the finding drawer says each thing once, in plain words

- The title reads like a sentence: a leading package prefix the scanner repeats is dropped ("django: Django SQL injection" → "Django SQL injection") or moved to the end ("Arbitrary command execution in PyYAML"), a secret is named by its kind and file ("Generic API Key in app/settings.py"), and a SAST finding uses the scanner's message instead of the rule slug. The stored title is unchanged.
- The line under the title names the CVE or rule, the package and version (or file and line) and the asset, instead of repeating the technique.
- The priority appears once, in "Why it matters", which now explains the deadline when it differs from the severity's window ("The deadline follows the priority (P2: 15 days), not the severity (critical: 2 days)"). The remediation-window text is translated.
- Tags show only labels people set (the scanner's tool name, finding type and file are left out); "Occurrences" reads "Seen in N scans"; the finding ID moved to the ⋯ menu ("Copy finding ID").
- The description renders `inline code` from advisories, is collapsed to four lines with "Show more", and no longer flashes the code snippet before the finding loads.
- The SLA window is no longer requested for a nil or free-text asset id.
