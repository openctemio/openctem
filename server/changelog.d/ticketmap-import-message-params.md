### Added: ticket field mapping issues and import preview warnings carry typed values

- Ticket field mapping validation issues, drift checks and preview notes now include `params` and,
  where one `code` covers several sentences, a `message_code` naming the exact sentence. Every
  existing `code` value and the English `message` are unchanged, so existing clients keep working.
- Import mapping preview warnings include `params` (counts).
- The web console uses them to show these texts in the reader's language.
- Docs: none (additive API fields used by the web console; the mapping guides are unchanged)
