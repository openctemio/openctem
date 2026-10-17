### Fixed: "Create ticket" shows only to who may create one

- The create-ticket action on the findings list, the finding drawer, the
  finding page and a remediation task's findings now needs the integrations
  module and `findings:write` (the API's gate) everywhere, through one hook;
  the findings list and the task page showed it to everyone. The label is
  translated (English and Vietnamese).
