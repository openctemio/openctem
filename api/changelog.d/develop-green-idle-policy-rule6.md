### Security: outbound requests refuse IPv6 site-local addresses; one internal-address list checked everywhere

- `pkg/httpsec` now always blocks `fec0::/10` (deprecated IPv6 site-local), which ctis addrscope, the deny list the sensors use, already treats as internal.
- Security lint rule 6 checks the API's blocked ranges against ctis addrscope itself now that sdk-go takes its deny list from it: every addrscope range must be blocked by the API, and the API may block nothing addrscope does not name. A missing ctis module fails the rule.
- The admin step-up inventory classifies `PUT /api/v1/admin/tenants/{tenantId}/idle/policy` (routine: it turns the idle policy on or off with a reason, audited; at worst an organization becomes read-only, nothing is deleted) and drops the removed `idle/exemption` route.
