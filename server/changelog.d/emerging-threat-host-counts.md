### Behaviour change: an emerging-threat alert counts hosts everywhere, and likely is its own number

- Every number of an alert now counts hosts, the rows of the alert page: a host that serves ports 80 and 443
  (two service assets, `http://host` and `https://host`) is one affected host in the list, the drawer, the
  stored counters, immediate messages, digests and digest e-mails. Before, each service counted.
- "Confirmed" means confirmed only. Likely matches (a version match below 80% confidence) were counted as
  confirmed; they are now their own number: "3 hosts confirmed, 1 likely, 2 possibly affected, 2
  internet-facing", in the same words in the console and in messages. With asset names turned on, a message
  names each host once.
- An alert that was already announced is announced again only for a host it did not hold or a host in a
  stronger tier (possible to likely or confirmed, likely to confirmed). One more port of a known host no
  longer puts the alert back into the digest.
- The Emerging Threat Score is unchanged: exposure points are the best single affected asset, never a sum,
  so duplicate services never raised a score. No alert changes its score or its level.
- API: `GET /api/v1/emerging-threats` and `/{id}` return `confirmed_hosts`, `likely_hosts`, `possible_hosts`,
  `internet_facing_hosts` and `critical_hosts` instead of `confirmed_assets`, `possible_assets`,
  `internet_facing_assets` and `critical_assets` (counted in the caller's data scope, as before). The outbox
  metadata of an alert message keeps `confirmed`, `possible` and `internet_facing`, now host counts, and adds
  `likely`.
- Migration `20261117053810_threat_alert_host_counts` (additive): `threat_alerts.likely_assets` and
  `threat_alert_assets.host_key`. At start the API fills the keys of existing alerts and recomputes their
  stored counters in short batches (100 alerts per transaction, 30 s statement limit, one replica at a
  time). Nothing is sent again; until an alert is filled its rows count as before. No operator step.
- Docs: server/docs/architecture/emerging-threat-alerts.md ("Counting hosts"); user guide
  user-guide/emerging-threats.md, "How an alert counts" (openctemio/docs#309)
