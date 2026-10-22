### Changed: cards no longer carry coloured left-border stripes

- The repository "never scanned" banner and the scan run-flow step cards drop the coloured left stripe; the step state is already shown by the icon and the state pill. A CI check now refuses new coloured left or top border stripes on cards (`stripe-ok:` allows an exception).
