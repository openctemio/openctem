### Security: EASM DNS checks only look up the tenant's own names

- The daily dangling-DNS and email-posture checks no longer resolve every
  unrejected domain asset. A name awaiting review (what a sensor report
  creates) is checked only while an active scope target of the tenant covers
  it and no approved exclusion removes it; confirmed, dependency,
  monitor-only and legacy (unrecorded) names are checked as before. A tenant
  or a hostile sensor can no longer make the platform's resolver look up
  arbitrary third-party names.
- **Upgrade note:** none. Names in review outside the scope stop being
  checked; confirm them or add a scope target to have them checked again.
