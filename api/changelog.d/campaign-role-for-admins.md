### Fixed: an organization admin who is on a campaign team keeps their campaign role

- An admin who is the lead (or another member) of a pentest campaign got "You do not have permission to access this resource" when opening the campaign (the test credentials list) and could not sign off its completion: campaign routes skipped resolving an admin's campaign role. The role is now resolved for admins too; admins who are not members still pass the campaign role checks as before, and still cannot read test credentials or sign off without joining.
