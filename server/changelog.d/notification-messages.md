### Behaviour change: readable channel notifications, one message model for every channel

- Slack, Teams, Telegram, e-mail, webhook and Splunk messages are built from one card: the headline once, the severity once (a line plus a coloured marker), the asset, what it is (title, CVE, KEV, EPSS, exposure class), why it matters, the next step, the organization, and one action button. The console link is never written into the text (it was shown defanged next to the button) and visible text carries no internal IDs.
- A channel has a detail level (`minimal`, `standard`, `full`) instead of the include-details switch. New channels are `standard`. Existing channels keep what they sent: details on became `full`, off became `minimal` (migration `notification_detail_level`); switch a channel to `standard` in Settings > Integrations > Notifications to get the asset, the reason and the next step.
- Message templates use a closed set of variables (`title`, `severity`, `asset`, `asset_type`, `what`, `why`, `next_step`, `organization`, `count`, `description`), are validated on save (400 for an unknown variable such as `{severity_emoji}`, `{url}`, `{body}` or `{timestamp}`), and never render raw braces: a stored template that no longer validates falls back to the default layout. New endpoint `POST /api/v1/integrations/notifications/preview` renders sample data with the same code; the channel dialogs show it live.
- Messages are written in the organization's default language (en, vi).
- The generic webhook and Splunk payloads add a `notification` object (schema `openctem.notification/v1`).
- API: `include_details` is replaced by `detail_level` on the notification channel endpoints.

### Fixed: new-asset notices link to the assets and label shared provider edges

- A notice of new internet-facing assets links to the assets (one asset, or the inventory filtered to the assets added in the window with the new `first_seen_before` filter), no longer to the scan run.
- Addresses inside a provider's published shared front-end ranges are labelled with the provider ("N new addresses on a shared provider edge") instead of being announced as the organization's internet-facing assets; listed addresses name the host they were resolved from.
