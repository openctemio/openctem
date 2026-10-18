### Security: registration logs no longer carry the e-mail address

The "user registered" log line records the user id only. The e-mail address was written to the log unescaped (a log-injection vector) and is personal data that logs should not keep.
