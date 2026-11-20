### Fixed: a filter token's trigger and clear button take its full height

- The trigger of a filter token ("Status: Pending") stopped inside the token's 1 px border, so on a phone it was 34 px high instead of the 36 px of every other control, and its clear button was a 28 px square. Both now take the token's full height, border included; the clear button still looks the same (every filter token).
- Docs: web/docs/ui-style-contract.md (filters)
