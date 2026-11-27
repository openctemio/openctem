### Changed: notifications in the redesigned console show in the reader's language

- The notification list and bell word each notice from its message code and values in English or
  Vietnamese, with capability keys, severities, counts and times in plain words. A notice
  without a code, or with a code this console does not know, shows its stored English text, and
  title and body always come from the same source.
- Older coverage notices whose stored text has one of the fixed sentence shapes are shown in the
  reader's language too; any other older notice shows as stored.
- Docs: server/docs/architecture/notification-system.md#message-codes
