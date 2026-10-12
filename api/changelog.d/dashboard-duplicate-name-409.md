### Fixed: a duplicate dashboard name is answered 409, not 500

- Creating or renaming a personal dashboard (`/api/v1/me/dashboards`) to a name you already use now answers 409 with the reason instead of 500.
