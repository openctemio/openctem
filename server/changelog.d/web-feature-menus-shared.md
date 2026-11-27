### Changed: every feature "..." menu uses the shared action menu

- The last 16 hand-built overflow menus (role members, comments, asset owners, inventory rows, related assets, the dashboard header and widget editor, the finding header and sub-statuses, pentest campaigns and steps, remediation campaigns and tasks, repositories, SCM connections, the vulnerability page) open as the shared action menu: anchored on a desktop, a bottom sheet on a phone, with the object's name as its title.
- An item that does not apply is shown with its reason (a first widget cannot move earlier, a full step list cannot add a step, a busy connection is being tested) instead of a bare disabled row; the repository and SCM connection menus gain a named trigger and translated labels.
- A menu left with one action shows that action as the button; the finding header's Copy link and the dashboard's Duplicate to mine are such cases.
- Docs: web/docs/ui-style-contract.md
