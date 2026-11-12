### Changed: the sensor list fits the screen and says why a sensor needs attention

- The list shows five columns by default (Sensor, Status, Version, Jobs, Tools) and fits a 1440 px screen without scrolling sideways. Outbox, Key, Local policy and Content are under **Display**; a problem in any of them now appears under the sensor's status in plain words ("420 results waiting, 2h", "no local policy: network jobs refused", "key expires in 3d", "added 5d ago, never connected"). The phone card uses the same words.
- A sensor at trust level New is tagged "Passive only" (what New means) instead of "New".
- A hint above the list counts the sensors that never connected for over a day or have been offline for over 7 days, and **Review them** lists only those, ready to select and delete or disable.
- Selected sensors can be disabled together (sensors:write), next to bulk delete.
- "Identity used from two hosts" shows on the row when the platform saw one sensor identity on two hosts.
