### Security: CI gate policies honour data scope, and loosening one needs step-up

- **Data scope on gate policies.** A repository policy is listed, created,
  changed and deleted only for a repository in the caller's data scope (404
  otherwise); before, every `scans:ci:read` holder saw every repository
  policy and every `scans:ci:write` holder could change the gate of any
  repository. Organization and business unit policies are changed only by a
  caller with an unrestricted data scope (403).
- **Loosening the gate needs step-up and is announced.** A policy change
  that lets more findings pass (warn mode, a higher severity threshold,
  new-findings-only, KEV off, a weaker EPSS threshold or mode, or disabling
  or deleting a stricter policy) asks for a recent sign-in like a
  break-glass, is audited at high severity (`ci_gate_policy.loosened`) and
  notifies every owner and administrator on the `ci.break_glass` event. It
  used to bypass break-glass entirely: one policy change disabled the gate
  for every commit. Tightening is unchanged.
