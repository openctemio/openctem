### Added: a known exploited (KEV) deadline cap in the SLA policy

- Each SLA policy has a "Known exploited (KEV) deadline cap" (`kev_cap_days`, default 14 days, 0 = off). A finding whose CVE is in CISA KEV is due at most that many days after the platform first sees it as known exploited, whatever its priority class or severity. The cap only tightens: a KEV flag that arrives later moves the deadline to now + cap, and nothing moves it later afterwards. Informational findings without an info SLA still get no deadline.
- A deadline the cap set is marked (`sla_kev_capped` on the finding), and the SLA timeline entry gives the reason `kev_cap`. Changes to the cap are audited; a longer cap or turning it off is High severity.
- Migration `sla_kev_deadline_cap`: two columns with constant defaults (no table rewrite) and two trigger functions replaced.

### Added: kev_ransomware on the findings list

- The findings list returns `kev_ransomware` for KEV findings whose CISA entry is marked as used in known ransomware campaigns (one KEV catalog query per page, only when the page has KEV findings), and the list accepts the filter `kev_ransomware=true|false`.
