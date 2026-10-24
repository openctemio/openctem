### Changed: every page is checked for the page layout rules, and CI/CD trust sections are one filter

- The web checks refuse a page that renders a page header without the shared page stack (product console and platform console), and a server page or layout that calls client hooks without `'use client'` (such a page crashed on every visit).
- The page rhythm browser check now visits every page of the console, read from the app directory, at 1440px and 390px: block gaps, one tab row, tab icons, metric strip rules, chips on one line, no pagination on an empty list, a readable name column, no sideways scroll, and no error page or page error.
- CI/CD › Trust and gate shows its sections (Trust, Gate policy, Break-glass, Pull request feedback) as a Section filter in a toolbar instead of a second row of tabs; the `?section=` links keep working.
