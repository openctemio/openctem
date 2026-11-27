### Changed: platform console CAPTCHA, Two-factor, Alerts and Leaked credentials settings

- The four pages use the settings page layout of the organization settings: one reading column of sections, the save bar pinned to the bottom (a full-width bar on a phone), and the same loading, load-failed and view-only states.
- A view-only administrator sees one "View only" notice at the top instead of a line at the end of each form.
- Secret fields (CAPTCHA secret key, alert webhook address and signing secret) use the shared secret field: masked, with Show value for what you just typed. A stored secret is still never sent back by the server.
- "Check the secret key" and "Send a test alert" are rows of their own, with a line saying what they check.
- The two-factor grace days say which members they apply to, and an invalid number is shown under its field.
- The console page checks run the layout-break detectors on the four pages with stored and fresh-install values, long names, on a phone, a tablet and a desktop, light and dark, English and Vietnamese.

- Docs: none (console page layout, no behaviour change in the API)
