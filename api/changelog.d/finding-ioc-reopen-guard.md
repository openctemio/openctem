### Security: the IOC reopen cannot overwrite a concurrent change; review flags pair a finding with its own tenant

- The IOC correlator reopens a resolved finding with an UPDATE that re-checks
  the status (`FindingRepository.ReopenResolved`), so a finding someone
  changed after it was read (for example accepted) is never overwritten. The
  reopen and its timeline entry commit together.
- `finding_decision_reviews` references `findings (id, tenant_id)` (migration
  `002207`, added NOT VALID; migration `002208` validates it), so a flag can
  never pair one tenant with another tenant's finding.
