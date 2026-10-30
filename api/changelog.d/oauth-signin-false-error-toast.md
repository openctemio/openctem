### Fixed: no false "Could not sign in" message when starting Google, GitHub, Microsoft or SSO sign-in
- Starting a social or SSO sign-in no longer shows a red error while the browser is already going to the provider (seen on iPhone Safari). The sign-in start now hands the provider address to the page, which opens it only when it is an https address; a real failure still shows the message.
