### Fixed: the assets list keeps typed search, its toolbar on errors, and explains an empty default list

- The search box no longer drops keys typed with short pauses ("repo-1" typed with pauses ended as "reo1"): the box keeps what is typed while its own debounced write comes back from the URL.
- A failed list read shows the error in place of the rows; the search, filters and views stay, so a bad search or filter from a shared link can be changed. Retry is in the error.
- A page number past the end (an old link, a list that shrank) shows the last page instead of an empty table.
- When the default list (which leaves out names awaiting review and names marked not yours) is empty, it says so and offers "Show all assets", instead of "No domains yet" over domains that exist or a plain "No assets match".
- With no other filter, the locked chip names how many it hides ("Hiding 80 names awaiting review or not ours"), so the heading count, the chip and the result count add up.
