# Team & Access

How to bring people into your team and control what they can do and see. These
screens live under **Settings → Organization**. Most actions require an
**admin** or **owner** role; a few are owner-only.

## Invite and manage members

Go to **Settings → Members** (`/settings/users`).

**Invite someone**

1. Click **Invite User** (top right).
2. In **Invite Team Member**, enter their **Email Address**.
3. Under **Assign Roles**, tick one or more roles (system and/or custom). At
   least one role is required.
4. Click **Send Invitation**.

The person appears under **Pending Invitations** until they accept. For a pending
invite you can **copy the invitation link**, **resend** it, or **cancel** it.

**Manage existing members**

Each member row has an actions menu:

- **View Details** — opens a side panel with their roles and info.
- **Change Role** / **Manage** — add or remove that member's roles, then save.
- **Suspend** / **Reactivate** — suspending blocks access without deleting the
  account (you'll be asked to confirm).
- **Remove Member** — removes them from the team (confirmation required).

The team **owner** row has no destructive actions — the owner can't be suspended
or removed. Use the stat cards (Total Members / Active / Pending / Roles) as
quick filters, and the **All / Active / Suspended** tabs to narrow the list.

## Team settings

Go to **Settings → Organization → General** (`/settings/tenant`). Four tabs:

- **General** — logo, Organization Name, URL Slug, Website, Industry, Timezone,
  Default Language. Click **Save Settings**. (Editable with the *Team Update*
  permission.)
- **Security** — **owner-only**. Require MFA for the whole team, set the session
  timeout, choose the email-verification mode, configure **Single Sign-On** per
  provider (Entra ID / Okta / Google Workspace), and set **IP Restrictions**.
  Click **Save Security Settings**. Non-owners see these controls disabled.
- **API & Webhooks** — enable API access and configure a webhook URL and its
  events, then **Save API Settings**.
- **File Storage** — choose where uploaded files live (Local / Amazon S3 /
  MinIO) and **Save Configuration**.

> On the **API & Webhooks** tab, in-app **API-key generation** and the **Test
> Webhook** button are not available yet (placeholders). To create programmatic
> keys today, use the API-key features under Integrations / MCP where offered.

## Roles and permissions

OpenCTEM uses **allow-only, role-based access control**: a member's abilities are
the union of the permissions granted by their roles. There are no "deny" rules
that subtract access. For the full model, operators can read the
[Authorization Matrix](../architecture/authorization-matrix.md).

There are four built-in **system roles**, from most to least powerful:

| Role | Can do |
|------|--------|
| **Owner** | Everything, including deleting the team and changing security/SSO settings |
| **Admin** | Manage members, roles, and most settings |
| **Member** | Create and edit resources (assets, findings, scans, …) |
| **Viewer** | Read-only |

### Create a custom role

Go to **Settings → Roles** (`/settings/roles`).

1. Click **Create Role**.
2. Give it a name and description, and select the permissions it should grant.
3. Save. The role is now assignable when you invite or manage members.

System roles are read-only; only **custom** roles can be edited or deleted. You
can only grant permissions you hold yourself — you can't create a role more
powerful than you.

Permissions come **only** from roles. Teams (below) decide which data a
member sees, never what they can do.

### Teams (data-scope groups) and Assignment Rules

Beyond *what* a member can do, you can control *which data* they see using
**Teams** and **Assignment Rules** under **Settings → Access Control**:

- **Teams** (`/access-control/groups`) — create a group (e.g. "Security Team"),
  and the assets attached to it define what its members can see. Use **Create
  Team**, then attach assets/members.
- **Assignment Rules** (`/access-control/assignment-rules`) — automatically route
  matching assets to a group. Click **Create Rule**, set a **Priority** (lower =
  higher priority), pick a **Target Group**, and add **Conditions** (by **Asset
  Type** and/or **Severity**). Use **Test Rule** to preview how many assets match
  before saving.

> Data-scope grouping currently applies to **assets and findings**. A member with
> no group assignment sees all of the team's data (the scope narrows only once
> they're assigned to a group).

### Audit log

Every access-control change (and much more) is recorded. Go to **Settings →
Organization → Audit Log** (`/settings/audit`) to review who did what and when.

## Your own account

See [Manage your own account](01-getting-started.md#manage-your-own-account) in
Getting Started for the Profile / Security / Preferences / Activity tabs
(password change, session revocation, theme, language).
