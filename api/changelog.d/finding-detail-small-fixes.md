### Fixed: finding page small fixes and remote images in descriptions

- Copy link reports a failed copy instead of "Link copied".
- The assignee picker is disabled without the assign permission.
- A verification plan that fails to load shows an error row with Retry instead of nothing.
- Dates on the finding page follow the app language; EPSS below 0.01% shows `<0.01%`.
- Strings and link hints that were not translated now go through the dictionaries; unknown tab keys are no longer shown raw.
- Raw palette colours, sub-12px text and uppercase labels on the finding tabs use design tokens; Sparkles is kept for AI content only; legacy remediation steps are read-only status rows; the Related tab drops its unlinked count tiles.
- Security: markdown from people (finding descriptions, notes) no longer loads remote images automatically. An image on another origin is shown as a link to its URL, so a tracking pixel cannot reveal the viewer's address or timing. The link, like every link in that markdown to another origin, sends no referrer (`rel="noopener noreferrer nofollow"`, `referrerpolicy="no-referrer"`). Relative and same-origin images, including attachments, still render.
