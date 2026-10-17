### Added: a new sensor product needs no platform change

- `SENSOR_PRODUCTS_FILE` names a file of extra sensor products, for example your own sensor built on the SDK.
  - The format is the `versions.yaml` product format, and `release_identity` may be `""`.
  - The products are added to the built-in catalog: the Sensors page lists them, the install dialog offers their snippets, and their sensors are judged against their own release line.
  - A file cannot redefine a built-in product or a fixed section. An invalid file stops the API from starting (RFC-094 I2).
- Install snippet templates are product data. They live in one directory per snippet set: `configs/sensor-products/<set>/<format>.tmpl`, with `sensor/`, `collector/` and `connector-tenable/` shipped.
  - Any well-formed `<set>/<format>.tmpl` in `SENSOR_CONFIG_TEMPLATES_DIR` is loaded, so a product's set is added without an API change.
  - `docker.tmpl` is required for each set.

### Changed: the templates directory layout

- **Upgrade note:** the default `SENSOR_CONFIG_TEMPLATES_DIR` is now `configs/sensor-products`. If you mounted edited templates over `configs/sensor-templates`, move them to the new layout:
  - `<format>.tmpl` goes to `sensor/<format>.tmpl`;
  - `collector-<format>.tmpl` goes to `collector/<format>.tmpl`;
  - `connector-tenable-<format>.tmpl` goes to `connector-tenable/<format>.tmpl`.
- Files left in the old layout are ignored, and the built-in templates are used instead.
