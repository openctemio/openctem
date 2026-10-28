### Fixed: release-train hotfix mode

- A hotfix can pick a PR's merge commit (cherry-picked by its first-parent diff).
- A hotfix runs the version checks with the previous tag's own scripts, so a later layout change no longer fails it.
- The post-release back-merge of a hotfix whose picks are all on develop is a `-s ours` merge instead of a conflict.
