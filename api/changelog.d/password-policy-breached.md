### Security: passwords are at least 12 characters and never a breached one

- The default minimum password length is now 12 (`AUTH_PASSWORD_MIN_LENGTH`;
  examples and compose files updated). Every new or changed password is also
  checked against an embedded list of about 47,000 of the most used breached
  passwords (SecLists Pwdb top 100k, MIT), case-insensitively, with no network
  call; one on the list is refused with a clear message.
- Existing passwords keep working: the rules apply when a password is set,
  reset or changed. The sign-in form no longer enforces a length.
- **Upgrade note:** a deployment that sets `AUTH_PASSWORD_MIN_LENGTH=8`
  explicitly keeps 8; raise it to 12.
