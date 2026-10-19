package ticketmap

import (
	"fmt"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/remediation"
	ticketmapdom "github.com/openctemio/openctem/api/pkg/domain/ticketmap"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// AssetInfo is what a finding's mapping may show about its asset.
type AssetInfo struct {
	Name        string
	Type        string
	Criticality string
}

// UserInfo is what a mapping may show about an assignee.
type UserInfo struct {
	ID    string
	Email string
	Name  string
}

// FindingValues flattens a finding into mapping values. Secret findings never
// expose their description: only the masked value reaches any field.
func FindingValues(f *vulnerability.Finding, asset *AssetInfo, assignee *UserInfo, webBase string) ticketmapdom.Values {
	v := ticketmapdom.Values{
		"finding.id":            ticketmapdom.Text(f.ID().String()),
		"finding.title":         ticketmapdom.Text(findingTitle(f)),
		"finding.url":           ticketmapdom.Text(strings.TrimRight(webBase, "/") + "/findings/" + f.ID().String()),
		"finding.severity":      ticketmapdom.Text(string(f.Severity())),
		"finding.status":        ticketmapdom.Text(string(f.Status())),
		"finding.source":        ticketmapdom.Text(string(f.Source())),
		"finding.tool":          ticketmapdom.Text(f.ToolName()),
		"finding.is_kev":        ticketmapdom.Bool(f.IsInKEV()),
		"finding.tags":          ticketmapdom.List(f.Tags()...),
		"finding.cwe_ids":       ticketmapdom.List(f.CWEIDs()...),
		"finding.sla_status":    ticketmapdom.Text(string(f.SLAStatus())),
		"finding.first_seen_at": ticketmapdom.Date(f.FirstDetectedAt()),
	}
	if pc := f.PriorityClass(); pc != nil {
		v["finding.priority_class"] = ticketmapdom.Text(string(*pc))
	}
	if c := f.CVSSScore(); c != nil {
		v["finding.cvss_score"] = ticketmapdom.Number(*c)
	}
	if e := f.EPSSScore(); e != nil {
		v["finding.epss_score"] = ticketmapdom.Number(*e)
	}
	if cve := strings.TrimSpace(f.CVEID()); cve != "" {
		v["finding.cve_ids"] = ticketmapdom.List(cve)
	}
	if p := vulnerability.DisplayPath(f.FilePath()); p != "" {
		v["finding.file_path"] = ticketmapdom.Text(p)
		loc := p
		if f.StartLine() > 0 {
			v["finding.start_line"] = ticketmapdom.Number(float64(f.StartLine()))
			loc = fmt.Sprintf("%s:%d", p, f.StartLine())
		}
		v["finding.location"] = ticketmapdom.Text(loc)
	}
	if d := f.SLADeadline(); d != nil {
		v["finding.sla_deadline"] = ticketmapdom.Date(*d)
	}
	if r := f.Remediation(); r != nil {
		if b := strings.TrimSpace(r.MobilizationBrief()); b != "" {
			v["finding.fix_guidance"] = ticketmapdom.Text(b)
		}
	}
	isSecret := f.Source() == vulnerability.FindingSourceSecret || f.FindingType() == vulnerability.FindingTypeSecret
	if isSecret {
		desc := "A secret was detected. The value is redacted; open the finding for details."
		if mv := f.SecretMaskedValue(); mv != "" {
			desc += " Masked value: " + mv
		}
		v["finding.description"] = ticketmapdom.Text(desc)
	} else if d := strings.TrimSpace(f.Description()); d != "" {
		v["finding.description"] = ticketmapdom.Text(d)
	}
	if asset != nil {
		v["finding.asset_name"] = ticketmapdom.Text(asset.Name)
		v["finding.asset_type"] = ticketmapdom.Text(asset.Type)
		v["finding.asset_criticality"] = ticketmapdom.Text(asset.Criticality)
	}
	if assignee != nil {
		v["finding.assignee"] = ticketmapdom.UserValue(ticketmapdom.UserRef{ID: assignee.ID, Email: assignee.Email, Name: assignee.Name})
	}
	return v
}

// maxTableRows bounds a task's findings table; the issue links to the rest.
const maxTableRows = 200

// TaskValues flattens a remediation task and its (already scope-filtered)
// member findings into mapping values. The task's priority is its most
// severe open finding's severity.
func TaskValues(t *remediation.Task, members []*vulnerability.Finding, totalMembers int64, assignee *UserInfo, webBase string) ticketmapdom.Values {
	base := strings.TrimRight(webBase, "/")
	closed := t.Counts.Closed
	progress := 0.0
	if t.Counts.Total > 0 {
		progress = float64(closed) / float64(t.Counts.Total) * 100
	}
	v := ticketmapdom.Values{
		"task.id":             ticketmapdom.Text(t.ID.String()),
		"task.title":          ticketmapdom.Text(t.Title),
		"task.url":            ticketmapdom.Text(base + "/remediation/tasks/" + t.ID.String()),
		"task.status":         ticketmapdom.Text(string(t.State)),
		"task.finding_count":  ticketmapdom.Number(float64(t.Counts.Total)),
		"task.resolved_count": ticketmapdom.Number(float64(closed)),
		"task.progress":       ticketmapdom.Number(progress),
	}
	if p := taskPriority(members); p != "" {
		v["task.priority"] = ticketmapdom.Text(p)
	}
	if d := strings.TrimSpace(t.Description); d != "" {
		v["task.description"] = ticketmapdom.Text(d)
	}
	if t.Deadline != nil {
		v["task.due_date"] = ticketmapdom.Date(*t.Deadline)
	}
	if assignee != nil {
		v["task.assignee"] = ticketmapdom.UserValue(ticketmapdom.UserRef{ID: assignee.ID, Email: assignee.Email, Name: assignee.Name})
	}
	tbl := &ticketmapdom.Table{Header: []string{"Finding", "Severity", "Status", "Location", "Link"}}
	for i, f := range members {
		if i >= maxTableRows {
			break
		}
		loc := vulnerability.DisplayPath(f.FilePath())
		if loc != "" && f.StartLine() > 0 {
			loc = fmt.Sprintf("%s:%d", loc, f.StartLine())
		}
		tbl.Rows = append(tbl.Rows, []string{findingTitle(f), string(f.Severity()), string(f.Status()), loc, base + "/findings/" + f.ID().String()})
	}
	if more := int(totalMembers) - len(tbl.Rows); more > 0 {
		tbl.More = more
	}
	v["task.findings_table"] = ticketmapdom.Value{Table: tbl}
	return v
}

// taskPriority is the most severe severity among the open members, mapped
// onto critical, high, medium, low ("" when none is open).
func taskPriority(members []*vulnerability.Finding) string {
	rank := map[vulnerability.Severity]int{
		vulnerability.SeverityCritical: 4, vulnerability.SeverityHigh: 3,
		vulnerability.SeverityMedium: 2, vulnerability.SeverityLow: 1,
	}
	best := 0
	for _, f := range members {
		if f.Status().IsClosed() {
			continue
		}
		if r := rank[f.Severity()]; r > best {
			best = r
		}
	}
	return [...]string{"", "low", "medium", "high", "critical"}[best]
}

// TaskStateOf maps a remediation task's state to the task state a status map
// uses.
func TaskStateOf(t *remediation.Task) string {
	switch t.State {
	case remediation.TaskStateDone, remediation.TaskStateClosedUnverified:
		return ticketmapdom.TaskDone
	case remediation.TaskStateCanceled, remediation.TaskStateArchived:
		return ticketmapdom.TaskArchived
	case remediation.TaskStateOnHold:
		return ticketmapdom.TaskBlocked
	case remediation.TaskStateVerifying:
		return ticketmapdom.TaskVerifying
	case remediation.TaskStateInProgress:
		return ticketmapdom.TaskInProgress
	}
	return ticketmapdom.TaskOpen
}

// findingTitle is the finding's title, or its message when it has none.
func findingTitle(f *vulnerability.Finding) string {
	if t := strings.TrimSpace(f.Title()); t != "" {
		return t
	}
	return strings.TrimSpace(f.Message())
}
