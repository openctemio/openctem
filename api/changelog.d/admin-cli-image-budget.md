### Fixed: admin-cli image size budget

- The release image check allowed the admin CLI image 30 MB; it is 34 MB since console sign-in gained WebAuthn and TOTP, which blocked publishing every v0.10.0 image. The budget is now 40 MB.
