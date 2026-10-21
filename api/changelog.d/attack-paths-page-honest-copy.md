### Fixed: the Attack paths page no longer claims what it cannot know, and reports load errors

- Removed the claim that "patching or isolating the top-ranked asset breaks the most attack paths". The ranking shows how widely each asset is exposed; it does not identify a choke point.
- Each row on Attack paths is now the ranked asset itself. It used to be drawn as a two-node "Internet-facing entry points → asset" path that the page never computed; real routes are on Exposure chains.
- When the API fails, Attack paths and Exposure chains show a load error with Retry instead of "No relationship data yet".
- A step on an exposure chain that the viewer may not see is shown as "Outside your access".
- The remaining hard-coded English on both pages and on the path graph is moved to the translation files (en and vi).
