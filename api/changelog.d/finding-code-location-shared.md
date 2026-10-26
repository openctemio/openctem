### Changed: the finding drawer and triage mode show the code location

- The finding drawer gains a Code location band for file findings without a data flow (IaC, SAST without a trace, any finding with a file and snippet): file and lines, branch, commit, the snippet with the finding's line highlighted, copy, and a link to the file at the commit. Secrets, web findings and traced findings keep their own panels.
- Triage mode shows the same band instead of a plain snippet block. One component now renders a finding's code location on the drawer, the Overview tab and triage mode; the link goes through the safe external link check.
