### Changed: forms, wizards and create or edit dialogs share one frame (redesign branch)

- New shared pieces in `web/src/features/shared/components/forms/`: `WizardFrame` (step strip, one footer row with the
  summary line, Back, Next and the primary action, one height for every step), `FormStack` / `FormSection` /
  `FormRow` / `FormField` (label above the field, "Optional" mark, help, the error under its field and tied to it),
  `useDiscardPrompt` and `LeaveGuard` (asking before unsaved changes are dropped), and `FormDialog` (title, scrolling
  body, footer with Cancel and one primary action).
- New scan and Edit scan use the shared wizard: a 56rem dialog, the steps as one strip at every width (it scrolls
  sideways on a phone), and the summary as one line in the footer that opens the whole summary. The permanent summary
  column is gone. Steps, fields, defaults, validation, permissions, the draft and every request are unchanged.
- The form kit (`FormItem`, `FormLabel`, `FormDescription`, `FormMessage`) uses the same label, help and error type.
- Docs: web/docs/ui-style-contract.md ("Forms, wizards and form dialogs")
