### Security: minting a sensor key and revealing a leaked credential need a recent sign-in

- `POST /api/v1/sensors` and `POST /api/v1/sensors/{id}/regenerate-key` mint a
  persistent sensor key, and now require step-up, as creating an API key
  already did. Revoking, disabling and deleting a sensor stay one click.
- `POST /api/v1/credentials/{id}/reveal` (the plaintext of a leaked
  credential) now requires step-up. It stays audited.
- `PUT /api/v1/sensors/identity-policy` requires step-up when it allows
  bearer-key sensors again. Requiring key-bound identity stays one click.
- The web console prompts for re-authentication and retries the request,
  as for API keys.
- **Upgrade note:** API clients that call these routes with a user session
  get `403 STEP_UP_REQUIRED` unless the session signed in or stepped up
  (`POST /api/v1/auth/step-up`) in the last 10 minutes. `oct_` API keys
  never reached them (keys are read-only).
