### Fixed: metric strips and the attack surface overview keep their place while loading

- A metric strip keeps its height while its numbers load (the value skeleton has the value's line height, and a tile with a detail line holds that line), so the blocks below no longer jump when the numbers arrive. Applies to every page with a metric strip.
- The attack surface overview shows its numbers, the discovery suggestions and the external surface together (at most 1.5 seconds after the first answer) instead of one after another (layout shift 0.11 to 0.17 before).
- The asset page shows its identity, timeline and side panels together once they answered (at most 1.5 seconds), so a panel that loads late or hides when empty no longer pushes the page (layout shift 0.08 at 1440px and up to 0.46 at 390px before, now 0 and 0.01).
