### Fixed: console write inventory and the address-list lint after recent merges

- The admin step-up inventory classifies `PUT /api/v1/admin/tenants/{tenantId}/idle/policy` (routine: it turns the idle policy on or off with a reason, audited; at worst an organization becomes read-only, nothing is deleted) and drops the removed `idle/exemption` route.
- Security lint rule 6 compares the private-range table with sdk-go and reports the always-blocked list as a tracked gap now that sdk-go takes it from ctis addrscope, until the API uses addrscope too.
