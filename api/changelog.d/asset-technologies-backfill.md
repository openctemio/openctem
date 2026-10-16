### Fixed: technology detections removed from asset software

- A background job (`asset-technology-backfill`, once per organization) fills the detected technologies
  of existing assets from what they already show, and removes the software component links earlier
  ingest created for detections that are not versioned software (security headers such as HSTS,
  hosting platforms, CDNs, analytics tags, names without a version). Real components stay. It works in
  batches of 500 rows and takes no long locks (RFC-112).
