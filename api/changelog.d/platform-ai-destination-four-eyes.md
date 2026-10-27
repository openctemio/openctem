### Security: changing where platform AI sends data needs a second super admin

- Saving the platform AI provider turned on with a different destination than the last one applied while on (provider, server address, private-network switch or API key) now needs another super admin's approval first (`platform_ai.destination`, 428 `SECOND_APPROVAL_REQUIRED`). The approval is bound to the exact destination, including a keyed fingerprint of the API key, so a key swap cannot ride on an approval for something else.
- Model and allowed-model changes and turning platform AI off stay one-person, so an incident response is never blocked. Removing the key of a platform that stays on is a destination change and asks. A save that carries a key is refused when the encryption backend cannot fingerprint it. With a single super admin the existing single-admin fallback applies (audited critical, every administrator told).
- The console's waiting dialog now reads "Waiting for a second administrator".
