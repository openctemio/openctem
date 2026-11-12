### Security: SCIM deprovisioning works when the SCIM feature is off

- The SCIM feature gate refused every request of an organization that lost the feature (and failed closed on a limits read error), including the DELETE and active:false calls an identity provider sends to remove a leaver. A disabled feature kept the leaver's access.
- A user DELETE, PUT or PATCH now passes the gate; the handler then accepts only a deactivating outcome (active:true is refused with 403). Creating users, reads and group changes stay gated.
