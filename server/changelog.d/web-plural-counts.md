### Fixed: counts use the singular for one item

- English text with a count says "1 asset", "1 finding", "1 day" instead of
  "1 assets": 672 catalog strings now carry plural forms, including the
  selection bar of every bulk list.
- The number inside a plural is grouped in the reader's language.
- A count shows grouped digits in Vietnamese too ("12.840 phát hiện đang mở"), and
  acronym plurals follow the count ("1 CVE", "7 CVEs").
- Docs: none (wording of existing labels; the user guides quote none of these counts)
