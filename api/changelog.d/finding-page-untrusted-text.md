### Fixed: finding page shows scanner code safely and drops empty facades

- Code snippets, stack frames, data-flow steps and file paths on the finding page show bidi and control characters as visible escapes, and a very large snippet is cut with a "Show more".
- The Related tab lists only groups that have findings; the Remediation tab no longer shows an always-empty progress header.
- Removed unused finding-page code (the standalone priority card, the pentest hero panel and the unused source-panel layout option).
