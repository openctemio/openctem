### Fixed: pages no longer call a switched-off module's API while the module list loads

The web treated every module as on until the organization's module list arrived, so pages such as Validation requested attack simulation and control testing even when an administrator had switched them off, and the browser showed 403 MODULE_NOT_ENABLED errors. A module now counts as off until the list has loaded.
