### Fixed: finding comments are read with their own tenant condition

- The queries behind `GET /findings/{id}/comments` and the comment count filtered by finding id only; tenant safety rested on the route guard and the service's finding check. Both queries now also filter by the caller's tenant, so a finding id of another tenant returns no rows even if a caller skips those checks.
