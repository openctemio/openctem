### Security: changing or archiving a finding lifecycle needs a recent sign-in

- `PATCH` and `DELETE /lifecycles/{id}` and `DELETE /lifecycle-sub-statuses/{id}`
  now need a recent sign-in or step-up, like publishing a lifecycle version.
