### Fixed: the attack surface overview counts one population

- The overview tiles (total, internet-facing, critical internet-facing) now open `/assets` with the same attribution the stats count, so a tile and its list show the same number. "View all" of the exposed assets opens the external page with the same internet-facing definition and attribution.
- The asset breakdown and the average risk score count only the attributed assets, like the total, so the breakdown sums to the total and the average ignores names marked not yours or still in review.
- Recent changes no longer list a rejected or needs-review name, as an addition or as a history change.
- Exposed-asset and recent-change rows link to the asset; the info button is no longer inside the tile link; long host names truncate on a phone; a failed Undo of "Not ours" says so; the compact decide panel shows one line when only name rules wait and renders nothing while loading.
