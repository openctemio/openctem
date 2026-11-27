### Changed: console privileged actions ask for the reason and the authenticator code in their own dialog (redesign branch)

- Console > Administrators: Make {role}, Mark / Unmark break-glass, Confirm last sign-in was a test, Remove identity
  provider binding, Reset two-step verification and Deactivate / Reactivate open the console's confirmation with a
  reason and a fresh authenticator code, instead of a plain OK. The code goes with the request (no second prompt over
  the dialog); the reason goes in the request body. The routes, permissions, step-up and second-approval rules are
  unchanged.
- Console > Content catalog: Import a bundle, Publish a package and Revoke ask for the reason and the code in the
  dialog (the API already required both and opened a second prompt for the code); Revoke also asks to type the
  version. The file chooser is in the console's language.
- Console > Sensors: Enroll a sensor asks for the name, lifetime, reason and code in one dialog instead of two.
- Every reason field shows an example for its own action instead of one generic example.
- Docs: https://docs.openctem.io/console/scanning/ (catalog and enrollment already say "a reason and a fresh code");
  the roster sentence of https://docs.openctem.io/console/security/ ("Each action asks for confirmation") is updated
  when the redesign ships
