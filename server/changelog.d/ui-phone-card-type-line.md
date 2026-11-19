### Fixed: the asset phone card's type line no longer breaks words or runs under the risk score

- On a phone, the asset card's second line said the type and then the asset's description on one line: the type was squeezed and broken inside the word ("IP Addres" / "s"), and a long description ran past the card and under the Risk score. The line now says the type and the asset's group; the type is never cut, the group ends in an ellipsis with its full name as a tooltip.
- Descriptions written by discovery ("Root domain auto-created from subdomain discovery") are no longer shown on the card; the asset's details still show the description, as the desktop row already did.

Docs: web/docs/ui-style-contract.md (one-line metadata, system text stays out of lists)
