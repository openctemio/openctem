### Fixed: a target behind a pending scope entry shows what is left, never Approve to the requester
- The scope check rows (New Scan preview, target picker, refused scans) show, for a target whose scope entry waits for approval, every remaining blocker with its action: the approval (who can approve, named only for people who may see the members; Remind approvers; Approve for another approver; self-approval with an authenticator code for the only owner when nobody else can approve), a tier the entry does not allow, and domain proof with Verify domain.
- The person who asked for the entry no longer sees an Approve button that the server would refuse.
- `POST /api/v1/scope/check` also returns `tier`, the probe tier the targets were checked at.
