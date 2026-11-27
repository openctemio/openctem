### Fixed: your own items are recognised on every page load (redesign branch)

- Seven places decided "is this mine" from a user id the page often does not have (the session cookie is not
  readable by the page). Approving your own exception request or finding disposition opened the normal approve
  dialog instead of the self-approval one, Cancel was missing on your own content request, the pentest checklist
  filter "Mine" showed nothing, an AI agent you own did not offer you Attest, Scan approvals did not mark your own
  request (no "You", Remind or Withdraw), and the new-scan draft was not kept per person.
- They now read the id from your profile through one shared hook; a source test keeps the other id out of these
  decisions.
- Docs: none (no user guide describes these marks; behaviour now matches what the guides already say).
