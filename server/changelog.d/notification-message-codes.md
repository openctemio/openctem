### Added: in-app notifications carry a message code for the reader's language

- Every in-app notification now stores a stable message code and typed values next to its English
  title and body (`message_code`, `message_params` in `GET /api/v1/notifications` and in the live
  push). The web console words the notice from its catalogs in the reader's language, so a
  Vietnamese console no longer shows English sentences or raw capability keys such as
  `capture.screenshot`. E-mail, chat and webhook deliveries keep the English text.
- Older notifications keep their stored text; nothing is rewritten.
- Migration `20261126054042_notification_message_code` adds two nullable columns (no table rewrite).
- Docs: server/docs/architecture/notification-system.md#message-codes
