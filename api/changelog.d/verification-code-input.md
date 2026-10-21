### Changed: one verification-code field and one step-up dialog in the web app

- Every web screen that asks for an authenticator code, a recovery code or the password before a sensitive action now uses the same field and dialog: sign-in second step, two-factor set-up, turning two-factor off, new recovery codes, the step-up prompt, self-approvals (exceptions, exposures, scope entries, finding requests, scans), the scan window override and sensor pairing.
- The field is one input drawn as six cells: one-time-code autofill, numeric keypad, paste of the whole code with spaces or dashes, IME-safe, one accessible label with the error announced. A complete code submits on its own where the code is the last thing asked for.
- Turning two-factor off offers "Use a recovery code instead" rather than one field for both kinds of code. The account two-factor card and the step-up prompt are translated (English and Vietnamese).
- No API change: the server still checks every code, its one-time use, the lockout and the step-up window.
