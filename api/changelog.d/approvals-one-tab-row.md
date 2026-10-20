### Changed: the approvals page has one tab row and a status lens

- Findings > Approvals shows one tab row, Finding requests and Group exceptions, each counting only the requests waiting for a decision (no count at zero).
- The status is a lens in the list toolbar (Pending, Approved, Rejected, All) instead of a second row of tabs. The page opens on Pending; `?status=all` lists every request, including canceled and expired ones.
- The four count cards and the search box are gone: the search box filtered only the rows of the current page, which hid matching requests on other pages.
- A web check fails when a file renders more than one tab row.
- A web check fails when a server-paged table keeps the built-in search box, which searches only the loaded page.
