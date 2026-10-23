### Fixed: Assets Needs attention no longer lists groups on every load

- The bulk action bar asked for the group list as soon as an asset list rendered, although the group picker only opens with the owner dialog. The list is now requested when that dialog opens, so the Needs attention pages (and the inventory) send one request fewer on a hard load.
