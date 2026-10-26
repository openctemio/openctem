### Fixed: asset list service facts always fit their cell, columns drop by priority

- The Service facts cell shows whole chips only: the HTTP status as its code ("301", coloured by
  class, the reason phrase in its tooltip), the port, then as many facts as the cell holds, and
  "+N" for the rest. No chip is cut at the cell's edge and the "+N" opener is always visible; it
  lists every fact, now including the CDN or edge a service is served through ("Behind Cloudflare").
- The asset list drops lower-priority columns (last seen, owner, exposure, criticality, open
  findings, in that order) when the table is too narrow, instead of scrolling sideways: at 1440px
  with the sidebar open it shows name, risk, scope, service facts and open findings. A column
  turned on under Columns stays on.
- A risk score with a queued rescore names the clock beside it in its tooltip and accessible name.
- The service facts popover has an accessible name.
