package vulnmatch

import "strings"

// NVDMatch is one cpeMatch statement of an NVD CVE record, as the feed
// reads it.
type NVDMatch struct {
	Criteria              string // CPE 2.3 name
	VersionStartIncluding string
	VersionStartExcluding string
	VersionEndIncluding   string
	VersionEndExcluding   string
}

// RangeFromNVD turns one vulnerable cpeMatch statement into a range for the
// criteria's product, whose CPE it also returns. ok is false for a statement
// that cannot be stored: a criteria that does not parse, a version that is
// "not applicable", or an exact version given together with bounds.
//
// The criteria's version (and update, "8.2" + "p1" → "8.2p1") is an exact
// version; otherwise the four bound fields give the range; with neither the
// statement covers every version.
func RangeFromNVD(vulnID string, m NVDMatch) (Range, CPE, bool) {
	c, err := ParseCPE(m.Criteria)
	if err != nil || c.Version == NA {
		return Range{}, CPE{}, false
	}
	r := Range{VulnID: vulnID, Scheme: SchemeGeneric, Edition: qualifier(c.SWEdition), Target: qualifier(c.TargetSW)}
	bounded := m.VersionStartIncluding != "" || m.VersionStartExcluding != "" ||
		m.VersionEndIncluding != "" || m.VersionEndExcluding != ""
	if c.Version != Any {
		if bounded {
			return Range{}, CPE{}, false
		}
		r.Exact = c.Version
		if u := qualifier(c.Update); u != "" {
			r.Exact += u
		}
		if _, ok := ParseVersion(r.Exact); !ok {
			return Range{}, CPE{}, false
		}
		return r, c, true
	}
	switch {
	case m.VersionStartIncluding != "":
		r.Start, r.StartIncl = m.VersionStartIncluding, true
	case m.VersionStartExcluding != "":
		r.Start = m.VersionStartExcluding
	}
	switch {
	case m.VersionEndIncluding != "":
		r.End, r.EndIncl = m.VersionEndIncluding, true
	case m.VersionEndExcluding != "":
		r.End = m.VersionEndExcluding
	}
	for _, b := range []string{r.Start, r.End} {
		if b == "" {
			continue
		}
		if len(b) > MaxVersionLen {
			return Range{}, CPE{}, false
		}
		if _, ok := ParseVersion(b); !ok {
			return Range{}, CPE{}, false
		}
	}
	return r, c, true
}

// OSVEvent is one event of an OSV range: exactly one field is set.
type OSVEvent struct {
	Introduced   string
	Fixed        string
	LastAffected string
}

// RangesFromOSV turns the events of one OSV range (in their order) into
// ranges: introduced opens a range ("0" means from the first version), fixed
// closes it exclusively, last_affected closes it inclusively, and a range
// still open at the end has no upper bound. Every listed affected version
// becomes an exact range. Events that do not pair up are dropped.
func RangesFromOSV(vulnID string, scheme Scheme, events []OSVEvent, versions []string) []Range {
	out := make([]Range, 0, len(events)/2+len(versions))
	open, isOpen := "", false
	for _, e := range events {
		switch {
		case e.Introduced != "":
			open, isOpen = e.Introduced, true
			if open == "0" {
				open = ""
			}
		case e.Fixed != "" && isOpen:
			out = append(out, Range{VulnID: vulnID, Scheme: scheme, Start: open, StartIncl: open != "", End: e.Fixed})
			isOpen = false
		case e.LastAffected != "" && isOpen:
			out = append(out, Range{VulnID: vulnID, Scheme: scheme, Start: open, StartIncl: open != "", End: e.LastAffected, EndIncl: true})
			isOpen = false
		}
	}
	if isOpen {
		out = append(out, Range{VulnID: vulnID, Scheme: scheme, Start: open, StartIncl: open != ""})
	}
	for _, v := range versions {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, Range{VulnID: vulnID, Scheme: scheme, Exact: v})
		}
	}
	return out
}
