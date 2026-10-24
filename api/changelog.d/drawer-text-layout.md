### Fixed: drawers use one text size per line and never break words letter by letter

- In the asset, finding, scan run and sensor drawers, label and value now share one size (the label is muted, not smaller), a metadata line is one size from start to end, and no text is smaller than 12px.
- The asset change history and the run timeline put the time, source and task on one metadata line under the event, and the sensor job list does the same, so no name is squeezed beside a fixed-width time column.
- Buttons in the sensor health callout all use the same small size.
