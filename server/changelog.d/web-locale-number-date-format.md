### Fixed: numbers and dates follow the console language

- Counts, table cells, dates and times are written in the reader's language
  ("12,840" / "12.840", "Nov 18, 2026" / "18 thg 11, 2026") instead of the
  browser's language, a hard-coded English format or a raw "12840".
- One set of format helpers (`web/src/lib/app-locale.ts`) serves code inside
  and outside components; a guard test refuses a raw `toLocaleString()`,
  `toLocaleDateString()`, `toLocaleTimeString()` or a hard-coded locale.
- Docs: none (formatting of existing values; the user guides show no number or date format)
