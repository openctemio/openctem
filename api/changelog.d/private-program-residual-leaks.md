### Security: private program assets no longer leak through tags, counts, suggestions or pushes

- The inventory tag filter and `program_assets=only` match, for anyone but an owner, only the system tags of programs not hidden from them, so they cannot reveal that a private program covers a shared asset. Asset responses show the same tag set.
- The EASM overview counts and the review queue leave out hidden private program assets in SQL (also for restricted members whose scope rows include one).
- Tag suggestions (`GET /assets/tags`) are limited to the caller's data scope.
- A live notification about a hidden asset or its finding is pushed only to owners and the program's members.
- An owner listing assets or findings is no longer treated as a non-member administrator.
