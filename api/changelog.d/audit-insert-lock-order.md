### Fixed: audit inserts no longer deadlock across tenants
- The hourly approval and acceptance expiry sweeps insert their audit rows in tenant order, and the DAST identity repair writes its audit rows after the findings it changes, so every transaction takes the per-tenant audit chain lock after its business-row locks and in one order.
