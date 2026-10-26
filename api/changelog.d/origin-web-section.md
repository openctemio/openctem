### Added: a Web section on the page of a web origin

- The page of an http_service or website asset has a Web section with an Overview (security header posture from the `http_posture` property, or a clear empty state when none is reported), and Endpoints, Parameters and Changes tabs that reuse the Web surface tables, filtered to that origin. Each tab exports CSV; cells starting with `=`, `+`, `-` or `@` are prefixed so a spreadsheet never runs them as a formula. Stored values render as text only, and the origin links only when it is an http or https URL.
