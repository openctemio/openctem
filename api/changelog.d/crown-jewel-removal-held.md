### Fixed: removing a crown jewel asks for the reason and waits for approval honestly
- The removal dialog previews what removing the flag does to the open findings and asks for the reason the API requires when an open P0 or P1 finding would drop; it shows the API's error instead of a generic one.
- A removal held for approval (202) changes nothing on the asset until it is approved, the business impact score and notes included, and the console says it is pending approval instead of "removed".
- `PATCH /assets/{id}/crown-jewel`: an omitted `business_impact_score` or `business_impact_notes` keeps the stored value.
