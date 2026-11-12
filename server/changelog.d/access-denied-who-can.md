### Changed: a refused page says what is missing and who can grant it

- A page the signed-in person may not open now shows the same notice as a refused read inside a page: the page's name, the missing permission by its id, which built-in roles hold it (for example "Owners and administrators have it"), and that an owner or administrator can give it through a role. It replaces an English-only "Access Denied" card that showed only the raw permission id.
- Every sentence of the notice and of permission-denied messages in toasts is translated (English and Vietnamese); the route table no longer carries English-only messages.
- A protected page no longer renders before the access check on the first load of an organization: it used to fire its reads first, so a person without the permission caused refused requests (each one a refused-action audit row) and saw the page flash before the notice. Unprotected pages still render at once; a background refresh of permissions keeps the open page mounted.
- Display only: the API still decides every request; no permission, role or route gate changed.
