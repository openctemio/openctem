package notifymsg

// SampleInput is the made-up event the console preview renders: no
// organization data is read for a preview.
func SampleInput(eventType string, level Level, locale, consoleBase string) Input {
	epss := 0.42
	in := Input{
		EventType:    eventType,
		Severity:     "high",
		Level:        level,
		Locale:       locale,
		Organization: "Example Corp",
		URL:          consoleBase + "/findings",
	}
	switch eventType {
	case "new_finding", "finding_reopened", "finding_priority_escalated", "sla_breach", "sla_warning", "finding_assigned":
		in.AggregateType = aggFinding
		in.Severity = "critical"
		in.Facts = &Facts{
			Title: "Remote code execution in the file upload handler", CVE: "CVE-2026-12345", KEV: true, EPSS: &epss,
			AssetName: "shop.example.com", AssetType: "domain",
			Description: "The upload endpoint accepts a crafted archive that writes outside the upload directory.",
		}
	case "new_exposure":
		in.AggregateType = aggExposure
		in.URL = consoleBase + "/exposures"
		in.Facts = &Facts{
			Title: "Admin panel reachable on port 8443", Class: "web_interface_exposed",
			AssetName: "admin.example.com", AssetType: "subdomain",
			Description: "A login page answered on https://admin.example.com:8443/login.",
		}
	case eventNewAsset:
		return sampleAssets(in, consoleBase)
	default:
		in.ProducerTitle = Headline(locale, eventType)
		in.ProducerBody = "Sample event text."
		in.URL = consoleBase + "/"
	}
	return in
}

// sampleAssets is the discovery the preview of new_asset shows.
func sampleAssets(in Input, consoleBase string) Input {
	in.AggregateType = "asset"
	in.Severity = "medium"
	in.URL = consoleBase + "/assets?internet_facing=true"
	refs := []AssetRef{
		{Name: "api.example.com"}, {Name: "203.0.113.10", From: "api.example.com"},
		{Name: "203.0.113.11", From: "www.example.com"}, {Name: "staging.example.com"},
		{Name: "198.51.100.7", From: "mail.example.com"},
	}
	f := &Facts{Count: 7}
	for _, r := range refs {
		f.Items = append(f.Items, r.Text(in.Locale))
	}
	in.Facts = f
	return in
}
