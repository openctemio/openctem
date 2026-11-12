### Changed: platform sensors have their own console page

- The console has a new Platform sensors page (Scanning group, shown with the `platform.sensors.read` permission). It holds the sensor enrollment card, the sensor list with pause and retire, and the instance scan zones. They were in the Fleet and Zones tabs of Platform scanning, which are hidden while shared scanning is not available in the release, so an administrator had no way to enroll or see a platform sensor (feed relay, passive discovery, AI worker). The page does not depend on that switch.
- Platform scanning keeps the policy, queue, egress and anomaly tabs and the instance switch, and links to the new page. The Overview tile for platform sensors opens it.
- No API change: the routes behind the page were never gated by the switch.
