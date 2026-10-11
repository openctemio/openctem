### Behaviour change: scope entries and exclusions need no approval outside Strict scan approval

- In the Off (default) and On scan approval modes, a member with `attack_surface:scope:write` adds or widens a scope entry directly (step-up re-authentication kept) instead of sending a request, and a new scope exclusion is in effect at once, recorded with its creator as `approved_by`. Extending an exclusion keeps it in effect, and taking one out of effect no longer needs a second person. Only Strict keeps member requests and the exclusion review (RFC-073 §6, RFC-054 §13).
- Pending entries and exclusions left from the old flow are not activated: they stay on the Approvals tab to approve or reject, or their requester removes them and adds them again.
- An unknown scan approval mode now counts as Strict for scope entries (fail closed).
- The scope dialogs follow the mode: no request or approval wording outside Strict (en and vi).
