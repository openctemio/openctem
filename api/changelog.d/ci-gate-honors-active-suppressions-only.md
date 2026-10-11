### Security: the CI gate honors a suppression only while its rule applies

- A finding passed the CI gate as suppressed whenever any suppression link
  existed for it. The expiry job reopens a finding when its rule expires but
  keeps the link row, and links can name rules that are pending or rejected,
  so an expired or never-approved suppression let a finding pass every later
  pipeline. The gate now counts a suppression only through an approved,
  unexpired rule of the run's own organization (RFC-051 section 6).
