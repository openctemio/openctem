### Changed: a list without its own phone card shows a compact card

- A list without its own phone card drew a tall grid of up to four label-over-value fields under the title, whether they held a value or not: labels over an empty value or a dash, a field repeating the title, and a later field (such as Last seen) left out. The card now has short rows: the title (the row's name column, up to two lines) with the status chip and the row menu, one muted subtitle line (the asset, owner, id or text column the page marked), and at most two fields that have a value; empty and dash-only values and a repeat of the title are left out, "0" is a value and stays. Nothing wraps under the title any more: a status too wide for the title line gets its own line, and labelled action buttons one trailing line.
- A field that is only a switch (Enabled on Workflows) reads "On" or "Off" beside it.
- Docs: web/docs/ui-style-contract.md (automatic phone card, a switch on a phone card)
