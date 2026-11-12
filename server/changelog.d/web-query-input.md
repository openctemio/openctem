### Added: one search box component with completion and fixes

- The web console has one shared search box, `QueryInput`: plain words search as before, and conditions such as `severity>=high kev=true -status:accepted last_seen<7d` are completed (fields, operators, enum values and ages, and the most frequent values with counts in your own access), checked by the server as you type, and shown with their first problem and a one-click fix ("did you mean"). Keyboard: Tab or Enter accepts a suggestion, Enter runs, Ctrl+Space opens suggestions, Up recalls the last query, Esc closes. English and Vietnamese.
- Recent queries are kept in this browser only and are cleared at sign-out, when the session ends and on organization switch.
- The remediation hub's "task from a query" dialog uses it and accepts the short form too (the task stores the long form the server prints).
