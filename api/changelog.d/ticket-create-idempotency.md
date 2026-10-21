### Fixed: a retried ticket create no longer opens a second issue

- Jira finding and task issues carry a marker in the create request (issue property `openctem` with the object, its kind and the integration, plus the label `openctem-ref-<object id>`); GitHub issues end with a hidden marker. Before creating, the platform looks the marker up and adopts the issue it finds, so a create whose response was lost, or whose link was not recorded, is recovered by the next attempt instead of creating a duplicate.
- Only a marker naming the same object, kind and integration (Jira) or the same finding and organization (GitHub) is adopted; if the lookup fails, the create is refused rather than risk a duplicate.
- New Jira issues created by the platform get one more label, `openctem-ref-<object id>`.
