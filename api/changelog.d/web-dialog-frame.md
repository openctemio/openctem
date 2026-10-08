### Changed: dialogs keep their title and actions in view while the form scrolls

- Dialogs, confirmations and side sheets share one frame: a fixed header (title, description, close), a body that is the only part that scrolls, and a fixed footer with the actions. The Add finding dialog uses it first; the other dialogs move onto it in follow-up changes.
- On phones a dialog opens as a bottom sheet that stays above the on-screen keyboard and brings the focused field back into view; the footer clears the home indicator. A dialog without its own height limit can no longer grow past the screen.
- Dialog widths are presets (`size`: sm, md, lg, xl, full) instead of per-dialog values. A governance test fails on a dialog that sets its own scroll, height or width.
- The Add finding and Import results buttons on the findings page have accessible names on phones, where they show only an icon.
