### Fixed: detail properties always show their value, beside their label

- Finding detail: the ID row shows the ID (its first eight characters in mono, the whole ID in the tooltip) with a small copy button, instead of a lone "Copy ID" text button where the value should be.
- Property rows on finding, asset, scan and remediation task details keep the label and the value side by side from 768 px: a long value or several values (tags, an e-mail, a list of owners) wrap inside the value column instead of dropping under the label, so every value starts at the same place. Phones keep one line per row.
- Finding detail: the Asset row also shows where on the asset the finding is (the port and protocol, the URL path or file:line), masked like the Findings list.
- Docs: none (layout fix, no behaviour change)
