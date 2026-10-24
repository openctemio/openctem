### Fixed: table headers and the workspace error screen are named and translated
- A table column with no visible header (row actions) names itself to screen readers, and the rows-per-page select says what it sets.
- When the workspace cannot load, the screen is translated; a rate-limited server (429) reads as busy instead of unreachable and is retried once after a short pause.
- Removed an unused pagination component with untranslated text.
