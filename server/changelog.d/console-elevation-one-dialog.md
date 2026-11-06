### Changed: platform console elevation in one dialog, shown in the header row

- Elevating the console session asks for the role, the duration, the reason and the authenticator code in one dialog; the separate "Confirm it is you" dialog no longer opens on top of it. A wrong code is shown under the code field. Administrators with a security key can leave the code empty and confirm with the key; a console that accepts only security keys asks for the key after Elevate.
- The read-only or elevated state is a compact control in the header row (role and end time, "End now") instead of a full-width banner on every page.
