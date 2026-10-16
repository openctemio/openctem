### Security: the list of ticket trackers exempt from the claim rules is fixed

- Only verified Jira and GitHub webhooks are exempt from the person-only fix
  claim rules; the list is now private to the findings domain, so no other
  code can add a source at run time.
