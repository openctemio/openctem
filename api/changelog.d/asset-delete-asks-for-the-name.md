### Changed: deleting an asset asks for its name

- Deleting an asset now asks the user to type its name: the delete detaches it from its groups, owners, relationships and scope, and the console has no way to bring it back. A bulk delete asks for the count (or the name when one asset is selected) at any size, names the action on its button ("Delete 3 assets") and lists the first assets it touches.
- When the asset is known to have findings, the dialog offers Archive (reversible) instead of a delete the API would refuse.
- Typed confirmations ignore surrounding spaces and Unicode composition, so a name typed with a Vietnamese input method or pasted still matches.
- The delete and archive notices are translated (English and Vietnamese).
