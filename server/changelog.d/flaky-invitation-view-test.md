### Fixed: the invitation page test no longer races its own pending transition

- The invitation page tests clicked "Open" and the sign-in step button while the accept request's transition was still pending, when the button is disabled and a click is rightly ignored. They now wait for the button to be enabled first. No product change.
