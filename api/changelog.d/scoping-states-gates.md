### Fixed: scoping pages show failures, honour permissions and guard busy actions
- Cycles, business units, business services, attacker profiles and the threat model show the shared error state with Retry when a read fails, instead of an empty list or a skeleton that never ends.
- Start a cycle, New cycle and Import program are shown only to users who hold the matching write permission; the programs list says when the user has no access.
- Creating a cycle or an attacker profile cannot be submitted twice, shows the API's message on failure, and a cycle's end date cannot precede its start date.
- Cycle dates written as a plain date show the right day in every timezone.
- The exclusions list has a status filter, the Scope strip no longer flashes 0 while loading, and clicking an active strip tile clears its filter.
- The program page and its form have loading states, a back link and a Cancel link; the letters page now has Vietnamese text and downloads keep their file extension.
- Saving a cycle's attacker profiles refreshes the list even when the save fails midway.
