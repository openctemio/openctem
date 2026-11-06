### Added: exposures for risky internet-facing services

- An internet-facing open port whose measured kind is risky (RDP, VNC, Telnet, SMB, NFS, databases, caches, search engines, Docker and Kubernetes APIs, industrial protocols, ...) raises a `risky_service_exposed` exposure under Exposed ports. Severity follows the kind (industrial protocols critical) and is raised when the service answered without credentials. A kind guessed from the port never raises one. A changed kind or a closed port resolves it automatically.
- Migration `20261105124942_risky_service_exposed` admits the exposure type.

### Changed: open port summaries name a service only when it was identified

- "Port 6379 (Redis) is open" was written from the port number alone. A port number now names a service only as a guess ("Port 6379 is open to the internet (probably Redis)"), and the open port exposure's identity no longer depends on the application protocol (it uses the transport).
