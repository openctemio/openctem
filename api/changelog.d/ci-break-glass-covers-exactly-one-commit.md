### Security: a CI break-glass override covers exactly one commit

- A gate override now needs the full commit id (40 or 64 hex characters) and
  matches only that commit. Before, an abbreviated id (7 characters or more)
  was matched as a prefix, so it also covered any other commit made to share
  the prefix (about 2^28 attempts for 7 characters).
- An override saved with an abbreviated id before this change no longer
  applies; create it again with the full id (overrides last at most 7 days).
