package integration

// MetaEmailOrgMail is the metadata key of an e-mail notification integration
// that says the organization's own mail (invitations, account setup, member
// notices, scheduled reports) is also sent through this relay. It is set on
// new integrations and absent (off) on those saved before it existed, so an
// existing channel never changes the sender of organization mail by itself.
const MetaEmailOrgMail = "org_mail"
