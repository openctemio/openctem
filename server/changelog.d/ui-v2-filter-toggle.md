### Changed: an on/off filter keeps its size when it is turned on (redesign branch)

- Lists have one on/off filter token (`FilterToggle`): the toolbar's height, filled while on, the same box in both states, an optional short label on a phone and a reason when it cannot be changed. Attack surface > Exposures uses it for "Primary assets", which no longer narrows by 2 px when turned on and moves nothing beside it.
- Docs: web/docs/ui-style-contract.md (list state), web/docs/ui/shared-kit.md
