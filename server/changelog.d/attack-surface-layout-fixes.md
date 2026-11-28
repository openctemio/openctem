### Fixed: exposure chains as one list, attack-path edges clear of nodes, distinct chart colours, review cards fit a phone

- Exposure chains: the ranked chains are rows of one bordered list (rank, the chain, KEV and critical counts, score, Open attack paths on one line from a tablet up) instead of a 170 px card per chain, most of which held a single node.
- Attack paths: an edge that skips a column (the internet straight to a target that is also reached through an entry point) bends through an empty slot reserved in each column it crosses, so it no longer runs through the entry card, and its label (CVE, likelihood) sits on that slot instead of over other text. The shared flow edge takes waypoints for this.
- Exposures › Misconfigurations, Assets by type: every slice has its own colour (the tail past the five series colours folds into a neutral "Other" that keeps the total), the legend text is in the muted ink with the swatch carrying the colour, and type names come from the asset type catalog ("IP address", translated on Vietnamese pages).
- Attack surface › Review, Suggested rules: the cards use the shared card tracks and wrap long names, so on a phone the first card no longer runs past the screen; Accept as rule is an outline button and Reject a quiet one, so nine cards no longer show nine filled primary buttons.
- Docs: web/docs/ui-style-contract.md
