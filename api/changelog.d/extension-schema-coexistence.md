### Fixed: core start-up and key rotation on a database that also holds an extension schema

- The administrator bootstrap and the credential encryption tool probe only the core schema, so a table of the same name in another schema (an extension's) never answers for a core table.
- Key rotation (`rekey`) sweeps every schema for values the old key still opens and refuses the rotation when it finds one outside the locations it re-encrypts, or a table the connecting role may not read, instead of leaving such a value unreadable under the new key.
