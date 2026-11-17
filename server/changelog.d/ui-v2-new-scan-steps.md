### Changed: the New scan and Edit scan steps use the shared form layout (redesign branch)

- Every field of the What, Targets, Options, Schedule and Review steps has its label above it, its help under it and
  its error tied to it (`FormField`); required fields no longer carry an asterisk, fields are required unless they
  say otherwise. Intensity is one row of three choices with the chosen one explained under it. What to run, Where it
  runs and When to run are radio cards without decorative icons; the fields of "Schedule for later" sit under the
  three cards. The Targets step shows "Selected targets" as a named section under the field.
- `ChoiceGroup` (the segmented choice) has the kit's 32 px track with 26 px segments from 640 px up.
- Fields, defaults, validation, permissions and requests are unchanged.
- Docs: none (layout only; the form rules are in web/docs/ui-style-contract.md "Forms, wizards and form dialogs")
