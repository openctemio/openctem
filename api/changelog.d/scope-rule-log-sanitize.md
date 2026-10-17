### Security: scope rule names are sanitized in logs

The name of a scope rule and the reconciliation error are sanitized before they are written to the log, so a crafted rule name cannot forge log lines.
