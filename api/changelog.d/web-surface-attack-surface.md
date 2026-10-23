### Changed: Web surface moves to Attack surface, and Suggestions there is named Review

- Web surface (origins, endpoints, the same path across origins and their changes) is now a tab of Discovery › Attack surface at `/attack-surface/web`. Its rows are web endpoints, not assets, so it no longer sits among the Assets tabs. It still needs `assets:read`.
- `/assets/web` is removed; open `/attack-surface/web` instead.
- The Attack surface tab that lists the decisions waiting for a person is named Review, so "Suggestions" no longer names two different queues.
