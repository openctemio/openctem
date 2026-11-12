### Fixed: the setup checklist names the real cause when user namespaces are unavailable

- The `runtime.sandbox_network` catalog gains `userns_disabled_host` (the host sets `kernel.unprivileged_userns_clone=0` or `user.max_user_namespaces=0`; the fix is the sysctl, keeping the AppArmor restriction on). `userns_blocked` now says the seccomp profile is the cause only when the host allows user namespaces, and `userns_restricted` points at an AppArmor profile that grants `userns` instead of loosening the host.
