### Changed: the exposure flow reads in one glance on a phone

- On a phone the dashboard's exposure flow puts the answer first: "Actionable now" with its priority split as one bar and four figures, the outcomes as a grid (Past SLA, In progress, Open, then the closures of the period), the five stages as a list, and the sources last. The card is about 1.4 screens instead of more than 1.5 (up to 3 with many sources), and every figure is a tap target of at least 44 px.
- Sources are a ranked bar list, the busiest first: rank by findings or by assets (discovery tools no longer show 0), group by tool or by source instance (sensor, CI project, connector, platform; remembered on this browser). Sources with nothing in the period fold into one line; a stale or failed source stays in view with its status. When a refresh changes the order, rows slide to their new place (none under reduced motion) and show how many places they moved. A source's tooltip shows received, new or reopened, seen again and not stored, the instances that fed it, and a link to the sensor.

### Fixed: the exposure flow showed the actionable total twice and contradicted itself

- The actionable total appears once (the ring centre on a desktop, the headline on a phone); the stray divider and the "open now, not part of the period" caption are gone; the funnel says "Findings received".
- The stage marked "Act here" kept its own state icon instead of a filled brand circle with a cross, so a colour no longer contradicts its icon; each stage figure names what it measures ("79% scanned", "8 open P0"), so counts and shares no longer read as one unit. The loop widget uses the same icons.
- The footnotes under the flow moved into the info popover, which already said the same; the info button and the "Show table" button have 44 px touch targets.
