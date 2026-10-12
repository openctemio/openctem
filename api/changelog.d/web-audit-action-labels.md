### Fixed: audit actions read as sentences, not as Title-Cased ids

- The organization audit log and account activity labelled an action by Title-Casing its id ("Sso Change Requested") while the sensor activity used a separate label list. All three now use one label source: "SSO change requested", "Organization settings updated", "API key created". Resource types in the audit log read the same way ("SSO change", not "sso_change").

### Fixed: identity providers are named, never shown by their id

- A pending SSO change (the approval card, the owner notification and e-mail, the audit message) said "add the google_workspace identity provider" and "change identity provider <id>". It now reads "add the Google Workspace identity provider \"Corp SSO\"" and "change the Google Workspace identity provider \"Corp SSO\" (client ID)". Changes proposed before the upgrade read "change an identity provider (...)".
- The account page and sign-in error messages name the sign-in method ("Google Workspace", "GitHub", "Email and password") from one label map.
