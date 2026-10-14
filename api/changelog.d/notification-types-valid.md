### Fixed: security and lifecycle notices reach the in-app inbox again

- Seven notification types were declared and sent but refused by the type check, so every such in-app notice was dropped with only a warning in the log: sensor grant changes (`sensor_security`), scope changes (`scope_change`), CI security (`ci_security`), member lifecycle (`member_lifecycle`), scan approvals (`scan_approval`), scan window overrides (`scan_window_override`) and attack surface digests (`attack_surface_digest`). They are accepted now, and a test keeps every declared type valid.
