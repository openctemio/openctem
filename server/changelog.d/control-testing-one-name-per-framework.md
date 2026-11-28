### Fixed: control testing shows each framework once, says "Not tested yet", and keeps Record result in the table

- A framework is stored and shown under one standard name: "cis", "CIS" and "CIS Controls" were three cards and three filters ("ISO27001" and "iso27001", raw "nist_csf" and "owasp_asvs" too). New control tests take the standard name; a migration renames existing rows; the framework cards group names that differ only in case, and the framework filter matches any spelling. An unknown framework keeps its name as written.
- A framework card with no test result yet says "Not tested yet" instead of a big "—" headline.
- The row's "Record result" button sits in a column as wide as the button; it was cut 44 to 89 px past the table's edge in the 48 px icon column.
- Docs: none (the control testing guide names frameworks by their standard names already)
