### Changed: findings views keep columns and density, show unsaved changes; Triage is the primary action

- A saved findings view now stores its columns and row density with its filters, sort and grouping. A view whose list has changed shows a dot on the view button, and its menu offers Save changes, Save as new view and Discard changes.
- Finding and Priority are always columns, including when no finding has a priority yet. The View menu lists columns by name, and the choice is kept in the page URL. Severity starts hidden in the Active view (Priority already includes it) and shown in other views.
- Triage is the primary button on the Findings page, with the count of findings to triage; `t` opens it. Until the focused triage mode ships, it opens the Needs triage view and the first finding. Add finding and Import results moved into an Add menu.
