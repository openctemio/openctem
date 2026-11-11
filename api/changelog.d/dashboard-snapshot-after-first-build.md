### Fixed: a dashboard opened before its first build shows the figures once they exist

- Opening a dashboard while the organization's dashboard data was still being built for the first time stored a snapshot in which every widget said "being built". That snapshot was served until its next scheduled refresh (an hour by default), so the figures stayed hidden long after they were ready.
- Opening the dashboard now computes it again as soon as the first build has finished; a snapshot of built data is served as before.
