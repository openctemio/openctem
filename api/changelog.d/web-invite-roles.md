### Changed: the invite dialog explains what will happen, and roles show their risk

- The invite dialog takes one primary role (built-in, then custom roles) and optional additional roles. As you type the address it previews what will happen: whether the person is outside your organization or uses a personal address, whether you will confirm your identity, whether they will need two-factor authentication, and an end of access only for someone outside. A policy refusal is a translated sentence under the address, and sending is disabled; server errors are shown as translated messages, never raw text.
- The role list no longer scrolls inside the dialog, so no card or focus ring is clipped. Every role shows a risk tier and what it views or changes, instead of a permission count, in the invite dialog, the role editor for a member, the roles table and the role details.
- Role details show "Template update available" with what the update adds and removes, and apply it on request. Creating a role from a template records the template.
- Pending invitations show "Outside" and "Two-factor required"; a resend sent too soon says so.
- Settings › Authentication: "Who can be invited" (anyone, verified domains only, verified and allowed domains) and "Require an end of access for people outside".
- The dialog, the role picker and these settings are translated (English and Vietnamese).
