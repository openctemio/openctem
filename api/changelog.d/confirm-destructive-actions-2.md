### Fixed: destructive actions in the console ask before they act (part 2)

- Unlinking an asset from a business unit or service, removing an asset from an asset group
  (quick view and the add-assets dialog), removing a member from a role, disabling a sensor,
  deleting a CI gate policy, revoking a break-glass override, merging duplicate assets, rejecting
  a scope change, and (platform console) removing an organization's limit override or blocking
  an AI application everywhere now open a confirmation that names the object and the consequence.
- Deleting or revoking a sensor from the sensor list asks for its name, and a bulk sensor delete
  asks for the count, as the sensor dialog already did.
