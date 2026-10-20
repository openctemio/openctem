### Security: editing a custom role is held to the editor's own permissions on both sides

- A delegated role manager can no longer strip a permission from a custom role (or drop its full data access) that they do not hold themselves; `PUT /api/v1/roles/{id}` now checks what the role carries today as well as what it will carry, as deleting a role already did.
- Making a role gain an approval permission (any `*:approve`) or another privileged permission, and giving a user a custom role that carries one, needs the actor's recent re-authentication. Before, only a role turning from plain to privileged did.
