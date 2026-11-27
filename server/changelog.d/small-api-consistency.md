### Fixed: archived pentest campaigns stay read-only, threat model generation says why it takes no name, revoked sensors are not shown online

- Editing an archived pentest campaign (`PUT /pentest/campaigns/{id}`), its name included, is refused with 409 until the campaign is reopened; nothing is stored. Completed campaigns stay editable.
- `POST /threat-models/generate` with a `name` answers 400 `THREAT_MODEL_NAME_FROM_SCOPE` instead of dropping it: a threat model is named after its scope and renamed with it on every regeneration.
- Revoking or disabling a sensor sets its health to offline at once; a revoked sensor that had just sent a heartbeat used to keep reporting "online".
- Docs: none (API answers now match the documented behaviour of these resources)
