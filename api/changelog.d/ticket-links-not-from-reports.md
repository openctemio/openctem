### Security: a report can no longer set a finding's ticket links

- The `work_item_uris` of an ingested finding (CTIS, and SARIF through it) are
  no longer stored as the finding's ticket links. The ticket sync acts on
  those links: it moved and commented on the linked issue, and a change of
  that issue moved the finding. A sensor or an imported file could point a
  finding at any issue of the organization's tracker, or block a real ticket
  ("already ticketed"). Only the platform (create ticket) or a person links a
  ticket now.
