### Changed: an on/off filter keeps its size when it is turned on (redesign branch)

- Lists have one on/off filter token (`FilterToggle`): the toolbar's height, filled while on, the same box in both states, an optional short label on a phone and a reason when it cannot be changed. Attack surface > Exposures uses it for "Primary assets", which no longer narrows by 2 px when turned on and moves nothing beside it.
- On a phone, Exposures shows Export as a named icon with a tooltip, so its end actions keep to about 40% of the toolbar's second line and the filter tokens keep their room.
- Docs: web/docs/ui-style-contract.md (list state), web/docs/ui/shared-kit.md
