### Security: port-scan caps apply to every port scanner, keyed by capability

- Two port-scan rules applied only to jobs of the tool named `naabu`, so any other tool running `scan.ports` or `discover.hosts` skipped them:
  - the caps on port scans of names (web ports only while an address the name resolves to may not be probed on its own; the low-impact ports for unclassified addresses);
  - the rule that a port scan without a port list may not run on a port-limited scope entry.
- Both now apply to every job whose capability is `scan.ports` or `discover.hosts`, whatever tool runs it (RFC-094 §4.6).
- A job that names no capability is judged by the capabilities its tool implements. A tool the platform does not know counts as a port scan (fail closed).
