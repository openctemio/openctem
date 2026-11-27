### Changed: graph pages share one frame (Attack paths, Exposure chains, Exploration)

- Attack paths: the target and path filters sit in one toolbar under the title row, with the legend and "How paths are
  scored" as popovers at its end. The graph fills the rest of the window. Choke points and the path score sit under the
  graph at every width; no panel stands beside it.
- Attack paths: a click or Enter on a step opens its detail over the page (role, asset type, exposure, criticality,
  step likelihood and its basis, the likeliest finding, open and known-exploited findings, paths through it). "View
  findings" is its first action and has focus, so Enter on a step and Enter again opens the step's findings. The list view opens the same detail from a step's name. Before, a step opened its
  findings list directly.
- Exposure chains: the ranked chains take the full width. A search by asset name and a Target filter (known exploited,
  crown jewel) narrow the chains in the browser; the legend and "How chains are built" open from the toolbar.
- Exploration: its filters are a named toolbar.
- No API change, no new dependency.
- Docs: web/docs/ui-style-contract.md ("Graph pages")
