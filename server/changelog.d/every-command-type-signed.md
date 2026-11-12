### Security: every command type is proven to carry a signed job

- An audit of every place a command is created or handed to a sensor found that all of them are signed when the platform advertises signed jobs: commands are signed when a claim hands them out (claim-N, claim by id and its replay, shared claim, protocol v3), and feed relay rounds and lookups are always signed. Sensors that pinned the job signer therefore refuse none of them.
- A new test claims one command of each command type both ways and verifies its envelope, and a guard test fails when a command type is added without joining the list the test ranges over.
- Docs: server/docs/architecture/job-signing.md ("Every job a sensor runs is signed")
