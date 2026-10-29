### Changed: attack paths page shows the routes to one asset

- `/attack-paths` now draws the routes from the internet through entry points and hops to a chosen asset on a flow canvas, with the finding and weight of every step, the score of the selected route as a breakdown, and the choke points ranked by how many routes a fix cuts ("Fix this to cut N of M paths"), each linking to exactly the findings it counts.
- Hover or focus a node to light its routes; the arrow keys follow the edges, `[` and `]` switch routes, Enter opens a step's findings. A list view of the same routes is one click away and the default on a phone.
- Steps outside your data scope show as "Outside your access" and the likelihood of a route through them is withheld. Each exposure chain links to the attack paths of its target.
