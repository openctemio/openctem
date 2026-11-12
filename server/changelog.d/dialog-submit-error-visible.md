### Fixed: a failed dialog action shows why, above the buttons

- A refused or failed submit in a dialog or sheet is now always visible and announced: the error sits in a fixed region directly above the footer buttons (`DialogSubmitError`, role alert) instead of at the top of the scrolling body, where it was out of sight when the person was at the bottom next to the submit button. Adding a refused target to scope (for example a government domain) showed no message at all.
- The scope refusals read in plain words and say what to do: a denied target now says the installation does not allow it (for example a government or military domain) and to ask the platform administrator if the organization is authorised; public suffix, address range and shared code host refusals are reworded, in English and Vietnamese. The request id shows as a small Reference line.
- Moved to the shared region: Add to scope, add user, invite, member access, transfer ownership, trusted organizations, setup link, group membership end, scan window policy and override, scan zone, CI repository settings, report template upload, sensor products, support access, and in the admin console create administrator, create first owner, elevation, confirmations, content packs, security keys and support sessions. A guard test keeps new dialogs from putting a submit error back in the body.
- Display only: the API still decides what is allowed.

### Fixed: the admin console never keeps a one-time code or a reason after a dialog closes

- The confirmations of the platform console that ask for a reason and an authenticator code (scan approval policy, shared sensors and their egress, anomaly thresholds, enrollment, platform sensor proof, sign-up policy and alerts, default limits, e-mail, legal texts, audit chain, scan zones) reopened with the code typed the previous time. The reason and code now live in one shared hook and are cleared every time the dialog opens or closes and after every answer; a refused code is cleared at once and its error is gone on the next opening.
- The reason is marked required with a hint saying so, and the cursor goes to the first empty field when the dialog opens.
