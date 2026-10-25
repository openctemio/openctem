### Fixed: the filter chips row no longer draws the locked chip under the next chip on a phone

- The chips row under every list toolbar measured its own content instead of the width it has, and squeezed the locked chip ("Informational hidden", "Show") under its content, so the next chip was drawn over it. The row now fills its width, nothing in it shrinks under its content, and when the locked chip, Add filter, the count and "+N more" do not fit on one line the locked chip takes a line of its own above the rest.
- On a phone the list search box takes the toolbar's first line, with saved views and group under it, so its placeholder is no longer cut short.
- The informational chip on findings is drawn with the shared locked chip, like the one on assets.
- Findings header: the Triage button keeps its label on a phone and names its count ("Triage, 75 findings to triage"); the phone card's CVE and scanner are separate items instead of a dot-separated string.
