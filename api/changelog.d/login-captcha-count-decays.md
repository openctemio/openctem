### Security: a successful sign-in no longer clears the address's failed sign-in count

- The count of failed sign-ins per client address only decays with time (15 minutes), so one
  account signing in from a shared address no longer lifts the CAPTCHA for other attempts from it.
- If the count cannot be read, the sign-in asks for the CAPTCHA instead of skipping it.
