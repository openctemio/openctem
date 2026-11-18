### Fixed: Settings pages follow the acceptance review (redesign branch)

- Modules: the "Reset to defaults" header button is drawn from the first frame (disabled while the modules
  load), so the header no longer grows by a line on a phone when the data arrives.
- Sign-in: the two-factor switches (owners and administrators, everyone, SSO proof) and the re-verification
  tiers (routine, sensitive, critical) are in the order of the design.
- Sensor job safety: the opt-ins are named in plain words ("Out-of-band callbacks", "Custom templates"); the
  technical names an operator meets on the sensor are kept as one secondary help line in mono.
- General: a refused save marks the field it was about (the field the answer names, or the one field the
  request carried) and shows the message under it instead of in a notice over the page title.
- Members: phone cards show the name over the card's width, the e-mail address once (also when the name is the
  address), role and status on one line, and the menu in its own column; long invitation addresses break inside
  the card. Dates follow the console language, and built-in role names are translated.
- Plain words in the settings catalogs (en and vi): "two-factor" for MFA on trusted organizations, "identity
  provider" for IdP, no "ingest" or "UUID" in asset lifecycle and AI masking texts.
- Docs: none (layout and copy; no route, permission or API change).
