### Fixed: one main action and whole names in the last places that cut them

- Lists with saved views (findings, vulnerabilities, assets): a changed view shows the Modified mark and one "Save view" menu (Save view, or Save changes and Save as new view for its owner, and Reset) instead of two buttons, so the view's name is no longer cut at 1024 px and the row's end stays still.
- Emerging threat detail: one main action and a More menu at every width; from 1280 px the other state moves no longer stand beside it as four equal buttons.
- Scan workflow editor: no idle disabled buttons at rest (Save draft shows while there are changes, Publish while a saved draft waits); the canvas fits its steps once they are measured, so steps that load after the canvas are no longer drawn past its edge, and the minimap is left out below 1536 px where it covered the steps.
- Capability tags read in words ("Subdomain discovery", "Discover subdomains") instead of an upper-case key ("DISCOVER.SUBDOMAINS").
- E-mail addresses wrap only before the "@" (the person's part and the domain each stay whole) instead of at a dot of the domain.
- A time in the last minute reads "just now" instead of "less than a minute ago", which was cut in date columns.
- The user menu's initials are hidden from assistive technology, so the button's name no longer has to repeat them.

Docs: none (layout and wording only, no behaviour change)
