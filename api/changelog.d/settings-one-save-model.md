### Changed: more settings pages save with the sticky save bar

- License policy, Vulnerability matching, Asset lifecycle and Finding approvals no longer have a Save button of their own: like the other settings forms, a bar appears at the bottom while there are unsaved changes, with Discard, Save changes (also Ctrl or Cmd+S) and a prompt before leaving the page with unsaved changes.
- Vulnerability matching and Asset lifecycle say who can open them with the shared notice instead of an "Insufficient permissions" alert; a failed load offers Retry the same way as every other page.
- Settings, Members: the Approve and Reject buttons of a request to join wrap on a phone instead of running off the card.
- Settings, Members: a person who cannot read invitations no longer sees a "Pending invitations 0" tile or the "cannot send email" notice meant for inviters.
- Accessibility: the settings rail's section headings meet the 4.5:1 contrast ratio (tenant app and console), the settings search no longer names a results region that is not on the page, and the information buttons on Risk scoring have a name.
- Security overview card: "1 risk, 1 warning" instead of "1 risks, 1 warnings".
- A pull request that adds a Save button of its own to a settings page, a hand-made "no permission" message, or a raw table in a page now fails the page-anatomy check, in the tenant app and in the platform console.
