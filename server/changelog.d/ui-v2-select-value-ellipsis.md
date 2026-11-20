### Fixed: a select value that does not fit ends in an ellipsis

- A choice field cut a chosen value longer than the field mid-word with no mark that the text went on (seen on the scope policy's one-off entries in Vietnamese on a phone). Every select now ends such a value, its placeholder and a custom value text with an ellipsis; the open list still shows options in full.
- The layout check that sweeps every page now flags a value cut this way: it no longer trusts a line clamp or an ellipsis on a box that cannot draw one.
- Docs: none (kit field behaviour; the field sizes in the UI style contract do not change)
