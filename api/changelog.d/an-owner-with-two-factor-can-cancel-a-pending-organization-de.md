### Fixed: an owner who signs in with two-factor can cancel a scheduled organization deletion

- After the authenticator code (or the forced two-factor setup), an owner of an
  organization waiting for deletion now gets the "Cancel deletion" prompt
  instead of "This organization is suspended". The cancel call is unchanged: it
  still needs the session's refresh token, which exists only after the second
  factor succeeded.
