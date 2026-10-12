### Changed: MODULE_NOT_ENABLED names the module and the reason

- A request refused by the module gate now carries
  `details: {"module": "<id>", "reason": "disabled_by_admin"}` with the same 403 and code,
  so clients can tell the user the feature is turned off for their organization. Plan
  entitlement reasons follow with RFC-064.
