### Fixed: the console follows the organization's modules the way the API does

- A beta module switched off stayed in the sidebar and led to a refused page.
- Exceptions follows the `suppressions` module (its API) instead of `findings`.
- Asset relations, the dashboard attack paths card, its exposure chains and the
  "Assets reachable" widget follow their modules (`relationships`, `attack_surface`):
  hidden or shown as turned off, never asked for and left empty.
- A page whose module is off says "Turned off for your organization" and offers
  administrators Settings > Modules, instead of "not included in your current plan"
  (plans do not gate modules).
