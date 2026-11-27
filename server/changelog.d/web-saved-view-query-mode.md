### Changed: a saved view in Query mode shows its filter as text and can be edited and saved there

- Opening a findings view in Query mode puts the view's own conditions in the field as query text. Until the text is changed the view stays open as saved.
- Applying another text makes that text the whole filter: the list no longer sends the view with it, so the view's conditions are not applied twice. The title keeps the view's name with Modified; Save changes (the view's owner) stores the new text in the view, Save as new view and Reset work as before.
- A findings view saved from a filter that chips cannot show (an OR across fields, a group) is stored as its checked filter and no longer fails to save.
- In Basic mode, conditions of a view that chips cannot show are one "Advanced filter" chip that opens Query mode with the text.
- Docs: web/docs/findings-list.md
