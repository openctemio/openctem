### Fixed: a range too wide for one scan target says why and can be split

- New scan → Targets named every refused typed line with one generic message. Each one now shows its own
  reason inline; a range wider than one target can hold says so with numbers (for example
  "10.0.0.0/8 has 16,777,216 addresses; the most one target can hold is 65,536 (/16)").
- A range that fits in at most 256 ranges of the widest accepted size gets a one-click
  "Split into N /16 ranges" action, in the Targets step and in the paste list.
