# Verification codes and step-up

How the web app and the console ask a person for an authenticator (TOTP) code,
a recovery code, a security key or passkey, or their password before a
sensitive action. The code is in `src/components/security/`
(`verification-code-input.tsx`, `step-up-dialog.tsx`); the console imports the
same components through `@/components/security`.

## The problem

Each screen used to build its own field: a plain text input with a different
label, width, length limit (6 or 8), digit filtering, autofill hint and error
placement on every screen. Some submitted on the sixth digit, most did not; the
recovery code was a free-text field with different rules in each place; the
console's step-up dialog, the app's step-up dialog and the three self-approval
dialogs were five separate dialogs with the same purpose.

## The decision

**One field, one dialog.**

### `VerificationCodeInput`

One real `<input>`. A numeric code is drawn as six cells behind it; the cells
are decoration (`aria-hidden`), so assistive technology sees one labelled text
field. One field (rather than one input per digit) keeps the platform's own
behaviour:

- `autocomplete="one-time-code"` and `inputmode="numeric"`: SMS and password
  manager autofill fill the whole code; phones show the numeric keypad.
- Paste of the whole code works, with or without spaces and dashes.
- IME composition is left alone until it ends (Vietnamese Telex/VNI,
  full-width input); full-width and Arabic-Indic digits become ASCII digits.
- Backspace and selection work as in any text field; the code is always
  left-to-right (`dir="ltr"`), also in a right-to-left layout.
- One accessible label, the expected length as its description, and the error
  in a `role="alert"` live region linked with `aria-describedby`.

The input stays rendered with transparent text, not hidden: password managers
and autofill skip invisible fields.

| Prop                                                             | Meaning                                                                                                                    |
| ---------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| `value`, `onChange(code)`                                        | The normalised code: separators dropped, cut to `length`.                                                                  |
| `onComplete(code)`                                               | Called once each time the code becomes complete (typed, pasted, autofilled). Pass the submit here to submit on completion. |
| `length`                                                         | Default 6.                                                                                                                 |
| `mode`                                                           | `numeric` (cells) or `alphanumeric` (one field, for recovery and pairing codes).                                           |
| `groups`                                                         | Alphanumeric only: printed groups, e.g. `[5, 5]` shows `abcde-fghjk`.                                                      |
| `label`                                                          | Default "Code from your authenticator app" or "Recovery code".                                                             |
| `error`                                                          | Marks the field invalid, shows the message and focuses the field.                                                          |
| `hint`, `disabled`, `required`, `autoFocus`, `id`, `name`, `ref` | As usual.                                                                                                                  |

Formats: an account recovery code is `ACCOUNT_RECOVERY_CODE` (10 characters,
`abcde-fghjk`); a console recovery code is 12 characters (`ABCD-EFGH-JKMN`); a
sensor pairing code is 8 (`K7QM-4ZTD`).

### `StepUpDialog`

The one dialog for proving it is you: the app's step-up prompt
(`StepUpDialogHost`), self-approvals (exceptions, exposures, scope entries,
finding requests, scans), turning two-factor off, new recovery codes, and the
console's step-up prompt.

- Title (default "Confirm it is you"), why the action needs it, and how long
  the confirmation lasts (`rememberNote`).
- Extra fields above the code (`children`, e.g. a reason); `ready` says when
  they are valid.
- Submits when the code is complete and `ready` (`autoSubmit`, default on), or
  from the button.
- "Use a recovery code instead" (`recovery`) and "Use your security key or
  passkey instead" (`passkey`, offered first when `preferred`, the only way
  when `required`).
- `factor="password"` for accounts without an authenticator.
- A refused proof: the message is shown on the field, the code is cleared (a
  used code cannot be replayed) and the field is focused. Too many attempts
  and a locked account get their own message.
- `notice` replaces the form when no code can be entered (sign in again,
  loading failed).

`onSubmit(proof)` sends the proof and throws to ask again; the dialog never
decides anything. The server checks the code, its one-time use, the lockout
and the step-up window.

### Forms that carry the code

Console settings forms send the code with the change (`totp_code`) rather than
opening a dialog. They use `StepUpCodeField` (console), which is the same field
plus the "leave it empty to confirm with your security key" hint when the
administrator has a key. Dialogs with several other fields (scan window
override, sensor pairing approval) use `VerificationCodeInput` directly.

## Tests

`src/components/security/__tests__/` covers paste with separators, autofill as
one change, backspace, completion firing once, disabled, IME composition, the
error live region and focus, recovery codes, the dialog's auto-submit, refusal,
rate limit, recovery and passkey alternatives and the password factor. The
call sites' own tests cover their flows.
