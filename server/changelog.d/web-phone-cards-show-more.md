### Changed: phone lists grow with "Show 25 more", and a finding card shows its id and time left

- Below 768px every list drawn as cards ends with one full-width "Show 25 more" button and a line such as "50 of 418" instead of the numbered pager. The cards on screen stay in place, the new ones come under them and the address keeps `per_page`, so a reload shows the same number.
- The button names what is left when that is less than 25 and goes when everything is shown. At 100 rows, the largest page the API returns, a line says to narrow the filters to see the rest.
- A finding card reads priority and row menu, title on up to two lines, asset and place, id (the CVE, else the rule id) and time left, then severity, status and one exploit mark. The checkbox in select mode and the row menu are touch targets of their own.
- A link with `per_page=75` is accepted by every list.
- Docs: web/docs/findings-list.md, web/docs/ui-style-contract.md, web/docs/ui/shared-kit.md
