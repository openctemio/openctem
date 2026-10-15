### Behaviour change: program identification is gated on a reported capability, not the SDK version

- A job that carries a bug-bounty program's headers or User-Agent goes only to a sensor that reports `http.identity@1`: its tools send the job's identification on every request. Before, any sensor whose SDK was v0.19.0 or later got it. The platform no longer judges a sensor by its SDK version (RFC-094, decision O2).
- **Upgrade note:** update sensors to a release that reports `http.identity@1` (openctemio/sensor#275 and later) before deploying this; until then, jobs on program targets that require identification wait (fail closed), and a claim by id answers `PROGRAM_RULES_UNSUPPORTED`.
