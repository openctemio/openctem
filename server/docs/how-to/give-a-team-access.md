# How to give a team access

> Tenant how-to: add people to a team and let them inherit what they need,
> without creating or managing roles. Design:
> [RFC-127](../rfcs/RFC-127-team-access-presets.md); rules:
> [authorization-matrix.md](../architecture/authorization-matrix.md) (Team access presets).

---

## 1. What a team can carry

A team carries two things, and every member inherits both the moment they are
added:

- **What members can do**: one or more **presets**, each a ready-made set of
  permissions for one kind of person (Security analyst, Vulnerability manager,
  Remediation owner, Auditor, CTEM program lead, and so on). Several presets are
  combined: members get everything any of them allows. Choose none for a team that
  only scopes data.
- **What members can see**: **Specific assets** (the team's scope rules and the
  assets assigned to it) or **All assets**.

When someone leaves the team, or their membership reaches its end date, they lose
both at once. You never create, edit or assign a role for this.

## 2. Set it up

1. Open Settings > Teams and create the team, or open an existing one.
2. In the **Access** section, pick the presets. Each shows what it is for and what
   it allows.
3. Choose what members can see. Keep **Specific assets** unless the team really
   needs everything.
4. Save, then add people on the Members tab, with an optional end date.

A person's profile lists what they inherit and from which team ("Access from team
Analysts"), with the end date of the membership.

## 3. Teams with elevated access

A team is marked **Elevated access** when it sees all assets or a preset carries a
privileged permission. Because anyone added to it gets that access:

- only an owner sets or changes the team's access, or the team itself, and is
  asked to sign in again first; every change is audited;
- adding or removing people needs the members permission (`team:members:write`),
  not only the team permission, so a team lead cannot put someone in;
- people from outside your organization, and service accounts, cannot join a team
  that sees all assets; an outside person invited to a team with elevated access
  falls under your two-factor rules for outside members;
- owner and administrator are never granted through a team.

## 4. Updates and limits

- When a preset's template changes, the team shows **Update available** with the
  difference. Review it and apply it; nothing changes until you do.
- The role behind a preset is managed by the team: it does not appear in
  Settings > Roles and cannot be edited, deleted or assigned by hand.
- A team has at most 8 presets, and 10 roles in all including any bound by hand.
- Deleting the team removes its presets.

## 5. API

| Call | Purpose |
|---|---|
| `GET /api/v1/groups/{groupId}/access` | The team's presets, scope mode and whether it is elevated |
| `PUT /api/v1/groups/{groupId}/access` | Set the presets and scope mode (`{"presets": ["security-analyst"], "scope_mode": "specific"}`) |
| `POST /api/v1/groups/{groupId}/access/upgrade` | Apply a newer template version to one preset |
| `GET /api/v1/users/{userId}/team-access` | What a person inherits from teams |
| `GET /api/v1/roles/templates` | The presets you can choose |
