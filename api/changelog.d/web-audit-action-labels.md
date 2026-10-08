### Fixed: audit actions read as sentences, not as Title-Cased ids

- The organization audit log and account activity labelled an action by Title-Casing its id ("Sso Change Requested") while the sensor activity used a separate label list. All three now use one label source: "SSO change requested", "Organization settings updated", "API key created". Resource types in the audit log read the same way ("SSO change", not "sso_change").
