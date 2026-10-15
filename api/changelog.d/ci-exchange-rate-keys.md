### Security: the CI token exchange is limited per organization and issuer, not per address alone

- `POST /api/v1/ci/oidc/exchange` used one budget of 60 a minute per client address. Hosted CI runners share egress addresses across customers, so one busy pipeline fleet, or an attacker running jobs on the same runners, could throttle every other organization's CI.
- The exchange now counts 60 a minute per organization + token issuer at one address, under a per-address backstop of 600 a minute, both shared by every API replica. The issuer is read from the token without checking its signature, only to choose the bucket; the address stays in the key so junk tokens naming an organization from elsewhere cannot use up its budget.
