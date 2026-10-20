### Security: the priority-rule dry run only covers findings the caller may see

- `POST /api/v1/priority-rules/dry-run` listed every open finding of the organization, so a role with `priority_rules:read` but a restricted data scope got finding ids and titles outside its scope in the sample. It now applies the caller's data scope and the pentest-campaign membership rule of the findings list; counts, distribution and sample cover only what the caller can see, and the run fails closed when the data scope is unavailable.
