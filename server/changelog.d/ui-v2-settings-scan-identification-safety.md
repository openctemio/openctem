### Changed: Scan identification and Sensor job safety follow the settings page pattern (redesign branch)

- `/settings/scanning/identification` is drawn with the shared settings parts: Requirement (the "Require
  identification on every request" switch and the missing-marker fix), What your scans send (User-Agent, request
  headers, the platform's headers, the advanced rotation list and query parameter) and What a target receives (the
  preview). Who changed it last sits beside the first section's title.
- `/settings/scanning/sensor-safety` shows two sections: Scan jobs (saved together through the save bar, loosening
  still asks first) and Sensor keys and shared sensors (each switch still applies at once and confirms when it
  loosens).
- The save bar names what changed and says when a save failed (the changes stay). Loading and a failed load look as
  on every settings page. Permissions, confirmations and every API call are unchanged.
- Docs: none (the pages keep their functions; the look is described in web/docs/ui-style-contract.md, "Settings pages")
