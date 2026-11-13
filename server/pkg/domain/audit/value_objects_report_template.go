package audit

// Organization report templates (RFC-076). A template shapes every report
// the organization sends out, so adding and removing one is recorded.

const (
	ActionReportTemplateUploaded Action = "report_template.uploaded"
	ActionReportTemplateDeleted  Action = "report_template.deleted"
)

// ResourceTypeReportTemplate is an organization report template.
const ResourceTypeReportTemplate ResourceType = "report_template"

var _ = registerActions("report_template", map[Action]Severity{
	ActionReportTemplateUploaded: SeverityMedium,
	ActionReportTemplateDeleted:  SeverityMedium,
})

func init() {
	configResourceTypes[ResourceTypeReportTemplate] = struct{}{}
}
