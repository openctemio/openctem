### Fixed: an emerging threat's score always matches its parts

- The emerging-threat list and detail sent a score with parts that did not
  give it when the stored parts were missing (a row with a score but an empty
  breakdown showed a score of 87 beside parts of 0, and the recommended action
  read the empty parts). `ets_breakdown` is now sent only when its parts,
  times the confidence, give `ets`, and is `null` otherwise; the recommended
  action then follows the vulnerability's exploitation evidence.
- The console shows parts only when they give the score, says in plain words
  how the points make the score (every point counts when the affected version
  is confirmed, else the share that counts), and says when the parts were not
  recorded instead of showing zeros.
- Docs: server/docs/architecture/emerging-threat-alerts.md
