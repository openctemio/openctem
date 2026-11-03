### Changed: platform console danger zones on organization and user pages

- Suspending and deleting an organization moved from the page header to a "Danger zone" at the end of its Overview tab; lifting a suspension stays in the header. Deleting still needs a fresh code, a reason and the organization's name typed back, and the API still asks for a second approver where the installation requires one.
- On a user's page, "Sign out everywhere", "Reset two-factor" and "Block account" are in a danger zone at the end of the page; the everyday actions stay under the name.
- Organization states ("Suspended", "Deletion scheduled") use the shared state pill.
