package asset

// One definition of "internet-facing" for the whole product: the asset's
// exposure is public, or a source said it is reachable from the internet
// (is_internet_accessible). Every surface that shows, filters or counts
// internet-facing assets uses IsInternetFacing or InternetFacingSQL, never
// one of the two columns alone (the column is written by few sources, so
// reading it alone showed "No" on public assets).

// InternetFacing is the rule on the two stored values.
func InternetFacing(isInternetAccessible bool, exposure Exposure) bool {
	return isInternetAccessible || exposure == ExposurePublic
}

// IsInternetFacing reports whether the asset is internet-facing.
func (a *Asset) IsInternetFacing() bool {
	return InternetFacing(a.isInternetAccessible, a.exposure)
}

// InternetFacingSQL is the same rule as a SQL predicate on an assets row
// aliased alias ("a", "assets").
func InternetFacingSQL(alias string) string {
	return "(COALESCE(" + alias + ".is_internet_accessible, FALSE) OR " + alias + ".exposure = 'public')"
}
