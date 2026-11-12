### Security: spreadsheet library on its v2.11.1 release

- The API builds with excelize v2.11.1 (the tagged release) instead of an untagged commit of the same line. The commit used before already carried the fix for CVE-2026-107223 (a worksheet column range that could exhaust memory when a workbook is changed), but the dependency scan reads an untagged commit as the release before it and kept reporting the advisory. The tagged release makes the fixed version explicit. No behaviour change.
