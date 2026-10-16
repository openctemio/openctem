### Fixed: remediation task counts use fix_applied only

- Remediation task counts no longer reference the retired `validated_fixed` status; a fix claimed and awaiting verification is `fix_applied` only (the validation result is its own field now).
