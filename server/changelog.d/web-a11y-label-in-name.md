### Fixed: controls are named by what they show, the finding properties are valid lists

- Voice control: the organization switcher, the search button, the Triage button, each finding row and every "Copy ID" button now carry their visible text inside their accessible name, so saying what is on screen activates them. Shortcut hints and the initials chip are drawn as decoration, and the search button states its shortcut through `aria-keyshortcuts`.
- In the findings list the title is the button that opens a finding; the CVE link next to it is no longer nested inside another control.
- The finding page and drawer list their properties, people and folded details as separate description lists, so screen readers announce terms and values correctly.
- Links inside running text are underlined (shared `link-inline` style); on /scope the link was told apart from the text around it by colour alone (2.3:1).
