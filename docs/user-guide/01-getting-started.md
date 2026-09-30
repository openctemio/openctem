# Getting Started

This is the end-user guide to OpenCTEM. It walks you through everything you do
in the web app, in the order you'll do it. If you're deploying or operating the
platform, see the [operator and developer docs](../README.md) instead.

> **New to CTEM?** OpenCTEM organizes its whole navigation around the five stages
> of Continuous Threat Exposure Management: **Scoping → Discovery →
> Prioritization → Validation → Mobilization**. You'll see those as the section
> headers in the left sidebar. Each stage has its own chapter in this guide.

## Create your account

1. Open the app and click **Sign up** on the login screen (or go straight to the
   registration page).
2. Fill in **First Name, Last Name, Email, Password, Confirm Password** and click
   **Create Account**.
3. Check your email and confirm your address, then return to **Sign in**.

If you arrived from a team invitation link, the email is pre-filled and the
invitation is carried through registration — just set a password.

### Signing in with your company account (SSO)

If your organization uses single sign-on, you won't create a password. Instead:

- Social sign-in buttons (**Google**, **GitHub**, **Microsoft**) appear on the
  login page **only when your platform has enabled that provider**.
- Organization SSO — a **Sign in with {your company}** button — appears when you
  reach the login page through your org's link (`?org=<your-org>`). Your
  administrator gives you this link. See
  [Configure Microsoft Entra ID](../how-to/configure-entraid.md) for the operator
  side of the setup.

Forgot your password? Click **Forgot password?**, enter your email, and click
**Send reset link**. The email contains a link to set a new password.

## Choose or create a team

A "team" (also called a tenant) is your isolated workspace — its own assets,
findings, members, and settings. What you see right after login depends on how
many teams you belong to:

- **No teams yet** → you land on **Set up your first team**. Enter a **Team name**
  (the **Team URL** slug is filled in automatically) and click create.
- **One team** → you go straight to its dashboard.
- **Several teams** → you land on **Select a Team**. Click the team you want to
  work in. You can also **Create a new team**, or **Sign out and use a different
  account**.

You can switch teams later, and create additional teams, from the same screen.

## Accept a team invitation

When someone invites you, you get a link to an invitation page that shows the
team name, the **role** you'll be given, who invited you, and when the invite
expires. Click **Accept Invitation** to join (you'll be asked to log in first if
you aren't already), or **Decline**. If you were invited under a different email,
use **Log in with different account**.

## Find your way around

Once inside a team you'll see the CTEM stages in the left sidebar, plus
**Insights** (dashboards and reports) and **Settings**. The rest of this guide
follows that structure:

| Chapter | Covers |
|---------|--------|
| [Team & Access](02-team-and-access.md) | Invite members, roles & permissions, your own account |
| [Scoping](03-scoping.md) | Attack surface, business units, crown jewels, CTEM cycles |
| [Discovery](04-discovery.md) | Scans, agents, assets, exposures, credentials |
| [Prioritization](05-prioritization.md) | Attack paths, threat intel, business impact, priority rules |
| [Validation](06-validation.md) | Pentest, attack simulation, control testing |
| [Mobilization](07-mobilization.md) | Remediation, tickets, SLA, exceptions, workflows |
| [Insights & Reports](08-insights-and-reports.md) | Dashboards, program health, reports |
| [Settings & Integrations](09-settings-and-integrations.md) | Modules, integrations, SSO/SCIM, notifications |

## Manage your own account

Open the account menu (your avatar, bottom of the sidebar) to reach four tabs:

- **Profile** — your name and avatar. Edit and **Save**.
- **Security** — **Change Password** (for password accounts; SSO users see
  "managed by {provider}" instead), and **Active Sessions**: revoke any single
  session, or **Sign Out All Others** to log out every other device instantly.
- **Preferences** — theme (Light / Dark / System), language (English / Tiếng
  Việt), and notification toggles. Click **Save Preferences**.
- **Activity** — a read-only log of your recent account activity, filterable by
  category.

> Two-factor authentication appears on the Security tab but is **not yet
> available** — the enable button is disabled ("Coming soon"). MFA can still be
> **required at the team level** by an owner (see [Team & Access](02-team-and-access.md)).
