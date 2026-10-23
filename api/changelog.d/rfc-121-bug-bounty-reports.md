### Added: design for bug-bounty and disclosure reports as findings

- RFC-121 records how reports from an organisation's bug-bounty program or disclosure program enter OpenCTEM: each report is a finding with source `bug_bounty` and a typed report object (channel and report id, researcher handle, reported severity, channel state, reward and disclosure as data), one finding per report, duplicate candidates suggested from the caller's data scope and never merged automatically, file import first, and no automatic AI triage of reporter text.
- New architecture page `docs/architecture/bounty-reports.md`. No behaviour change in this step.
