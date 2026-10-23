### Changed: console colours, type and radius follow the brand

- Light mode uses the paper ground and ink text; dark mode uses the ink ground with surfaces derived from the ink hue. Teal marks only the place to act (focus ring, a page's primary call to action, links). Corners are smaller (4, 6 and 8 px by role).
- The console ships its own fonts: Inter for text and JetBrains Mono for identifiers, with Vietnamese subsets, served from the console itself.
- Chart colours keep out of the teal accent band; one categorical colour changed from green-teal to violet, and the dark heatmap ramp starts lighter so empty and low cells stay visible on the new dark cards.
- Severity colours come from shared tokens, with text that meets WCAG AA in both themes.

### Security: no font CDN in the console's content security policy

- The console's policy no longer allows `fonts.googleapis.com` or `fonts.gstatic.com`; fonts and styles load from the console's own origin only.
