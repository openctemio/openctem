### Changed: the console says content packs are not delivered to sensors yet

- No sensor downloads content packs yet and no scan job references one, so a stored pack is not used by any scan and revoking one stops nothing. The console's Content packs page now says so in a notice and shows packs as "Stored, not delivered" instead of "Active", until sensor delivery ships. Custom templates still travel inside each scan job.
