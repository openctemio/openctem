### Security: the admin console sign-in no longer reveals a correct password

- With "require identity provider" on, a correct password for a non-emergency administrator used to get a 403 (`IDP_SIGN_IN_REQUIRED`) while every other failure got a 401, so one request per guess told an attacker whether the password was right. Every refused password sign-in now gets the same 401 "Wrong email or password". The refusal is still audited and still counts toward the lockout. The sign-in page shows the identity provider hint and button after any refused password sign-in when a provider is configured.
