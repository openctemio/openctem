### Fixed: a silent sensor is no longer shown online, and the sensor drawer agrees with itself

- The liveness ladder caps a stored heartbeat deadline at the sensor's last contact plus the longest heartbeat interval the protocol allows (5 minutes). A far-future deadline (clock jump, restore, bad write) can no longer keep a dead sensor "Online" and routable.
- The sensor drawer's health checklist and the fleet "Needs attention" count now include the sensor's setup checks and unhardened posture, so the Overview no longer says all checks pass while Setup & health shows warnings.
