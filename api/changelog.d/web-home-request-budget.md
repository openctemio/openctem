### Fixed: the home page request budget matches the stored-dashboard home

- The home page now reads the viewer's and the organization's dashboard lists in addition to the session, so a viewer with no stored dashboard makes 5 API requests (session, support access, two dashboard lists, built-in overview). The end-to-end request budget for `/` is 5; no request repeats.
