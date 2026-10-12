### Fixed: the CI/CD page's pipelines, runs and OIDC banner are translated

- The CI/CD page header and tabs, the pipelines view (metrics, columns,
  search, empty states), the runs view and run details, the "Require OIDC for
  CI" banner and the Sensors page link card now use the console's English and
  Vietnamese catalogs. Copy no longer names only two CI systems or tells
  people to run the sensor in a CI job; the header links one CI integration
  guide. A test checks that every CI/CD key exists in both catalogs.
