### Security: one secret redactor for Jira and GitHub tickets; private keys no longer leak into GitHub issues

- GitHub issue bodies removed only the header line of a private key, so the key body reached the issue. Jira and GitHub now share one redactor that removes the whole key block (also a block whose footer is cut off), JWTs, AWS `AKIA`/`ASIA` key ids, GitHub, Slack and Google tokens, bearer values and secret assignments.
- The mobilization brief and the campaign epic description are redacted, capped and encoded like finding text, so they cannot add links, mentions or macros to a ticket.
