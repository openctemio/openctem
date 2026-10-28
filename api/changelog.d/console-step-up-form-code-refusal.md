### Fixed: console confirmations no longer freeze after a refused authenticator code

- A console form that asks for its own authenticator code (System > E-mail and
  every other settings form with a code field) no longer opens the console's
  step-up dialog on top of its confirmation when the code is wrong or was
  already used. That second dialog dimmed the confirmation, put its code field
  out of reach and kept its Confirm button disabled. The refusal is now shown
  under the form's own code field, which is cleared and focused for the next
  code. Codes asked for by the step-up dialog itself are asked for again as
  before. No API change.
