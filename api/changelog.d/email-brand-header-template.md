### Changed: email header rendered by a template, not string building

- The brand header of every email is now a named html/template sub-template (the app name is escaped by the template engine); the rendered output is unchanged.
