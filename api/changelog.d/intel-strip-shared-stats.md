### Fixed: the vulnerability page's intel strip uses the shared stat cells

- The intel strip drew its own label and value list, which the shared key-value guard refuses, so develop's web tests failed. It now uses `DetailStatGrid` and `DetailStat`; `DetailStat` gains `wrapCaption` so a longer caption (date added to KEV, ransomware use) wraps instead of being cut.
