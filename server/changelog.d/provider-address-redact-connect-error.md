### Fixed: the provider-addresses command no longer prints a database password

- When it could not open or reach the database, the `provider-addresses` command printed the driver's error text, which can quote a malformed `DATABASE_URL` with its password. The text now has the password removed and names the connection in its redacted form.
