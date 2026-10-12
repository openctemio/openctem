package report

import (
	"sort"
	"strings"

	"github.com/openctemio/openctem/api/pkg/report/docx"
)

// Template reference: every value a report template can read, with its type,
// a description (en, vi) and an example from the sample data. It is the one
// source of truth for the tag reference in the console, the published guide
// and the static tag checks (TemplateSchema). A test keeps it equal to what
// TemplateData produces.

// TemplateField is one value a template can read.
type TemplateField struct {
	Key         string    `json:"key"`              // unique: "campaign.name", "finding.title"
	Path        string    `json:"path"`             // what a tag reads: "campaign.name", "title"
	Group       string    `json:"group"`            // report, campaign, client, stats, findings, finding, retests, retest, team, team_member, labels
	Within      string    `json:"within,omitempty"` // item fields: the list to loop over ("findings", "retests", "team")
	Type        docx.Kind `json:"type"`
	Items       string    `json:"items,omitempty"` // lists of objects: the group of each item's fields
	Description string    `json:"description"`
	Example     string    `json:"example"`
	Tag         string    `json:"tag"` // ready to paste
}

type fieldSpec struct {
	group, path string
	kind        docx.Kind
	items       string // KindList: item group
	en, vi      string
}

// Item groups and the list a template loops over to read them.
var itemGroupList = map[string]string{
	"finding": "findings", "retest": "retests", "team_member": "team",
	"checklist": "checklists", "checklist_section": "checklist_sections", "checklist_item": "checklist_failed_items",
}

var fieldSpecs = []fieldSpec{
	{"report", "report.title", docx.KindText, "", "The report type's name in the template language.", "Tên loại báo cáo theo ngôn ngữ của mẫu."},
	{"report", "report.type", docx.KindText, "", "Report type: executive_summary, technical_report, finding_report, compliance_report, remediation_report or retest_report.", "Loại báo cáo: executive_summary, technical_report, finding_report, compliance_report, remediation_report hoặc retest_report."},
	{"report", "report.language", docx.KindText, "", "Language of the template's built-in labels: en or vi.", "Ngôn ngữ của các nhãn dựng sẵn: en hoặc vi."},
	{"report", "report.generated_at", docx.KindText, "", "Date the report was generated, YYYY-MM-DD.", "Ngày tạo báo cáo, dạng YYYY-MM-DD."},
	{"report", "report.classification", docx.KindText, "", "Classification: public, internal, confidential or restricted.", "Mức phân loại: public, internal, confidential hoặc restricted."},
	{"report", "report.classification_label", docx.KindText, "", "The classification in the template language, for a header or cover.", "Mức phân loại theo ngôn ngữ của mẫu, dùng cho đầu trang hoặc bìa."},
	{"report", "report.watermark", docx.KindText, "", "Watermark text chosen when generating the report; may be empty.", "Chữ watermark chọn khi tạo báo cáo; có thể trống."},

	{"campaign", "campaign.name", docx.KindText, "", "Campaign name.", "Tên chiến dịch."},
	{"campaign", "campaign.description", docx.KindMarkdown, "", "Campaign description (Markdown): use {@campaign.description} alone in a paragraph.", "Mô tả chiến dịch (Markdown): dùng {@campaign.description} đứng riêng một đoạn."},
	{"campaign", "campaign.type", docx.KindText, "", "The campaign's target types in words, comma-separated.", "Các loại mục tiêu của chiến dịch, viết bằng chữ, cách nhau bởi dấu phẩy."},
	{"campaign", "campaign.targets", docx.KindTextList, "", "Target type values; loop with {#campaign.targets}{.}{/campaign.targets}.", "Các giá trị loại mục tiêu; lặp bằng {#campaign.targets}{.}{/campaign.targets}."},
	{"campaign", "campaign.status", docx.KindText, "", "Campaign status, such as planning, in_progress or completed.", "Trạng thái chiến dịch, ví dụ planning, in_progress, completed."},
	{"campaign", "campaign.approach", docx.KindText, "", "Testing approach: black_box, grey_box or white_box.", "Cách tiếp cận kiểm thử, black_box, grey_box hoặc white_box."},
	{"campaign", "campaign.environment", docx.KindText, "", "Environment tested, production, staging, development or other.", "Môi trường được kiểm thử, production, staging, development hoặc other."},
	{"campaign", "campaign.tlp", docx.KindText, "", "Traffic Light Protocol marking: clear, green, amber, amber_strict or red.", "Mức chia sẻ TLP: clear, green, amber, amber_strict hoặc red."},
	{"campaign", "campaign.methodology", docx.KindText, "", "Testing methodology, such as OWASP WSTG or PTES.", "Phương pháp kiểm thử, ví dụ OWASP WSTG, PTES."},
	{"campaign", "campaign.start_date", docx.KindText, "", "First day of testing, YYYY-MM-DD.", "Ngày bắt đầu kiểm thử, dạng YYYY-MM-DD."},
	{"campaign", "campaign.end_date", docx.KindText, "", "Last day of testing, YYYY-MM-DD.", "Ngày kết thúc kiểm thử, dạng YYYY-MM-DD."},

	{"client", "client.name", docx.KindText, "", "Client organization name.", "Tên tổ chức khách hàng."},
	{"client", "client.contact", docx.KindText, "", "Client contact as entered on the campaign.", "Thông tin liên hệ của khách hàng như nhập trong chiến dịch."},

	{"team", "team", docx.KindList, "team_member", "The campaign team; loop with {#team}…{/team}. No e-mail addresses.", "Nhóm thực hiện; lặp bằng {#team}…{/team}. Không có địa chỉ e-mail."},
	{"team_member", "name", docx.KindText, "", "Team member's name.", "Tên thành viên."},
	{"team_member", "role", docx.KindText, "", "Team member's role on the campaign, such as lead or tester.", "Vai trò trong chiến dịch, ví dụ lead, tester."},

	{"stats", "stats.total", docx.KindNumber, "", "Number of findings in the report.", "Số phát hiện trong báo cáo."},
	{"stats", "stats.critical", docx.KindNumber, "", "Number of critical findings.", "Số phát hiện mức nghiêm trọng."},
	{"stats", "stats.high", docx.KindNumber, "", "Number of high findings.", "Số phát hiện mức cao."},
	{"stats", "stats.medium", docx.KindNumber, "", "Number of medium findings.", "Số phát hiện mức trung bình."},
	{"stats", "stats.low", docx.KindNumber, "", "Number of low findings.", "Số phát hiện mức thấp."},
	{"stats", "stats.info", docx.KindNumber, "", "Number of informational findings.", "Số phát hiện mức thông tin."},
	{"stats", "stats.avg_cvss", docx.KindNumber, "", "Average CVSS score of the findings that have one, one decimal.", "Điểm CVSS trung bình của các phát hiện có điểm, một chữ số thập phân."},
	{"stats", "stats.max_cvss", docx.KindNumber, "", "Highest CVSS score, one decimal.", "Điểm CVSS cao nhất, một chữ số thập phân."},
	{"stats", "stats.has_critical", docx.KindBool, "", "Yes when there is at least one critical finding; for {#stats.has_critical}…{/stats.has_critical}.", "Có khi có ít nhất một phát hiện nghiêm trọng; dùng {#stats.has_critical}…{/stats.has_critical}."},
	{"stats", "stats.has_high", docx.KindBool, "", "Yes when there is at least one high finding.", "Có khi có ít nhất một phát hiện mức cao."},

	{"findings", "findings", docx.KindList, "finding", "The findings in the report, most severe first; loop with {#findings}…{/findings}.", "Các phát hiện trong báo cáo, nghiêm trọng nhất trước; lặp bằng {#findings}…{/findings}."},
	{"findings", "findings_by_severity.critical", docx.KindList, "finding", "Only the critical findings; same fields as each finding.", "Chỉ các phát hiện nghiêm trọng; cùng trường như mỗi phát hiện."},
	{"findings", "findings_by_severity.high", docx.KindList, "finding", "Only the high findings.", "Chỉ các phát hiện mức cao."},
	{"findings", "findings_by_severity.medium", docx.KindList, "finding", "Only the medium findings.", "Chỉ các phát hiện mức trung bình."},
	{"findings", "findings_by_severity.low", docx.KindList, "finding", "Only the low findings.", "Chỉ các phát hiện mức thấp."},
	{"findings", "findings_by_severity.info", docx.KindList, "finding", "Only the informational findings.", "Chỉ các phát hiện mức thông tin."},
	{"findings", "has_findings", docx.KindBool, "", "Yes when the report has findings; {^has_findings}…{/has_findings} shows content when it has none.", "Có khi báo cáo có phát hiện; {^has_findings}…{/has_findings} hiển thị nội dung khi không có."},

	{"finding", "number", docx.KindText, "", "Finding number in report order: 1, 2, 3…", "Số thứ tự phát hiện trong báo cáo: 1, 2, 3…"},
	{"finding", "title", docx.KindText, "", "Finding title.", "Tiêu đề phát hiện."},
	{"finding", "severity", docx.KindText, "", "Severity: critical, high, medium, low or info.", "Mức độ: critical, high, medium, low hoặc info."},
	{"finding", "severity_label", docx.KindText, "", "Severity in the template language.", "Mức độ theo ngôn ngữ của mẫu."},
	{"finding", "status", docx.KindText, "", "Status, such as confirmed, fix_applied or resolved.", "Trạng thái, ví dụ confirmed, fix_applied, resolved."},
	{"finding", "status_label", docx.KindText, "", "Status in the template language.", "Trạng thái theo ngôn ngữ của mẫu."},
	{"finding", "cvss_score", docx.KindText, "", "CVSS score with one decimal; empty when none.", "Điểm CVSS với một chữ số thập phân; trống nếu không có."},
	{"finding", "cvss_vector", docx.KindText, "", "CVSS vector string; may be empty.", "Chuỗi vector CVSS; có thể trống."},
	{"finding", "cwe", docx.KindText, "", "CWE identifier; may be empty.", "Mã CWE; có thể trống."},
	{"finding", "cve", docx.KindText, "", "CVE identifier; may be empty.", "Mã CVE; có thể trống."},
	{"finding", "owasp", docx.KindText, "", "OWASP Top 10 category; may be empty.", "Hạng mục OWASP Top 10; có thể trống."},
	{"finding", "description", docx.KindMarkdown, "", "Description (Markdown, may embed evidence screenshots): use {@description} alone in a paragraph.", "Mô tả (Markdown, có thể chèn ảnh bằng chứng): dùng {@description} đứng riêng một đoạn."},
	{"finding", "business_impact", docx.KindMarkdown, "", "Business impact (Markdown).", "Ảnh hưởng nghiệp vụ (Markdown)."},
	{"finding", "technical_impact", docx.KindMarkdown, "", "Technical impact (Markdown).", "Ảnh hưởng kỹ thuật (Markdown)."},
	{"finding", "remediation", docx.KindMarkdown, "", "Remediation advice (Markdown).", "Khuyến nghị khắc phục (Markdown)."},
	{"finding", "poc", docx.KindText, "", "Proof of concept as plain text; empty when the report leaves proofs of concept out.", "Bằng chứng khai thác dạng văn bản; trống khi báo cáo không kèm bằng chứng khai thác."},
	{"finding", "steps", docx.KindTextList, "", "Steps to reproduce; loop with {#steps}{.}{/steps}.", "Các bước tái hiện; lặp bằng {#steps}{.}{/steps}."},
	{"finding", "targets", docx.KindTextList, "", "Affected targets (hosts, URLs); loop with {#targets}{.}{/targets}.", "Mục tiêu bị ảnh hưởng (máy chủ, URL); lặp bằng {#targets}{.}{/targets}."},
	{"finding", "references", docx.KindTextList, "", "Reference links; loop with {#references}{.}{/references}.", "Liên kết tham khảo; lặp bằng {#references}{.}{/references}."},
	{"finding", "has_steps", docx.KindBool, "", "Yes when the finding has steps; for a heading shown only then.", "Có khi phát hiện có các bước; dùng cho tiêu đề chỉ hiện khi đó."},
	{"finding", "has_targets", docx.KindBool, "", "Yes when the finding has affected targets.", "Có khi phát hiện có mục tiêu bị ảnh hưởng."},
	{"finding", "has_references", docx.KindBool, "", "Yes when the finding has references.", "Có khi phát hiện có tham khảo."},
	{"finding", "is_critical", docx.KindBool, "", "Yes for a critical finding; for severity-specific content.", "Có với phát hiện nghiêm trọng; dùng cho nội dung theo mức độ."},
	{"finding", "is_high", docx.KindBool, "", "Yes for a high finding.", "Có với phát hiện mức cao."},
	{"finding", "is_medium", docx.KindBool, "", "Yes for a medium finding.", "Có với phát hiện mức trung bình."},
	{"finding", "is_low", docx.KindBool, "", "Yes for a low finding.", "Có với phát hiện mức thấp."},
	{"finding", "is_info", docx.KindBool, "", "Yes for an informational finding.", "Có với phát hiện mức thông tin."},
	{"finding", "created_at", docx.KindText, "", "Date the finding was reported, YYYY-MM-DD.", "Ngày ghi nhận phát hiện, dạng YYYY-MM-DD."},

	{"retests", "retests", docx.KindList, "retest", "Retest results; loop with {#retests}…{/retests}.", "Kết quả kiểm tra lại; lặp bằng {#retests}…{/retests}."},
	{"retests", "has_retests", docx.KindBool, "", "Yes when there are retest results.", "Có khi có kết quả kiểm tra lại."},
	{"retest", "finding_title", docx.KindText, "", "Title of the retested finding.", "Tiêu đề phát hiện được kiểm tra lại."},
	{"retest", "finding_severity", docx.KindText, "", "Severity of the retested finding.", "Mức độ của phát hiện được kiểm tra lại."},
	{"retest", "finding_severity_label", docx.KindText, "", "That severity in the template language.", "Mức độ đó theo ngôn ngữ của mẫu."},
	{"retest", "status", docx.KindText, "", "Retest result: passed, failed, partial, pending, in_progress or canceled.", "Kết quả: passed, failed, partial, pending, in_progress hoặc canceled."},
	{"retest", "status_label", docx.KindText, "", "Retest result in the template language.", "Kết quả theo ngôn ngữ của mẫu."},
	{"retest", "notes", docx.KindText, "", "Tester's notes.", "Ghi chú của người kiểm thử."},
	{"retest", "tested_at", docx.KindText, "", "Date of the retest, YYYY-MM-DD.", "Ngày kiểm tra lại, dạng YYYY-MM-DD."},

	{"checklists", "checklists", docx.KindList, "checklist", "The methodology checklists the campaign ran; loop with {#checklists}…{/checklists}.", "Các danh mục kiểm thử của chiến dịch; lặp bằng {#checklists}…{/checklists}."},
	{"checklists", "has_checklists", docx.KindBool, "", "Yes when the campaign ran at least one checklist.", "Có khi chiến dịch có ít nhất một danh mục kiểm thử."},
	{"checklists", "has_checklist_failures", docx.KindBool, "", "Yes when at least one checklist item failed.", "Có khi có ít nhất một hạng mục không đạt."},
	{"checklists", "checklist_summary.total", docx.KindNumber, "", "Number of items in all checklists.", "Số hạng mục trong mọi danh mục."},
	{"checklists", "checklist_summary.passed", docx.KindNumber, "", "Items that passed.", "Số hạng mục đạt."},
	{"checklists", "checklist_summary.failed", docx.KindNumber, "", "Items that failed.", "Số hạng mục không đạt."},
	{"checklists", "checklist_summary.not_applicable", docx.KindNumber, "", "Items marked not applicable.", "Số hạng mục không áp dụng."},
	{"checklists", "checklist_summary.untested", docx.KindNumber, "", "Items without a result.", "Số hạng mục chưa có kết quả."},
	{"checklists", "checklist_summary.tested", docx.KindNumber, "", "Items with a result (passed, failed or not applicable).", "Số hạng mục đã có kết quả (đạt, không đạt hoặc không áp dụng)."},
	{"checklists", "checklist_summary.coverage", docx.KindNumber, "", "Share of items with a result, in percent, one decimal.", "Tỷ lệ hạng mục đã có kết quả, theo phần trăm, một chữ số thập phân."},
	{"checklists", "checklist_sections", docx.KindList, "checklist_section", "Coverage of each checklist section; loop with {#checklist_sections}…{/checklist_sections}.", "Độ bao phủ của từng mục; lặp bằng {#checklist_sections}…{/checklist_sections}."},
	{"checklists", "checklist_failed_items", docx.KindList, "checklist_item", "The checklist items that failed; loop with {#checklist_failed_items}…{/checklist_failed_items}.", "Các hạng mục không đạt; lặp bằng {#checklist_failed_items}…{/checklist_failed_items}."},
	{"checklist", "name", docx.KindText, "", "Checklist name.", "Tên danh mục kiểm thử."},
	{"checklist", "standard", docx.KindText, "", "Standard the checklist follows, such as OWASP WSTG; may be empty.", "Tiêu chuẩn của danh mục, ví dụ OWASP WSTG; có thể trống."},
	{"checklist", "standard_version", docx.KindText, "", "Version of the standard, such as 4.2; may be empty.", "Phiên bản tiêu chuẩn, ví dụ 4.2; có thể trống."},
	{"checklist", "template_version", docx.KindNumber, "", "Version of the organization's checklist template the campaign ran.", "Phiên bản mẫu danh mục mà chiến dịch đã dùng."},
	{"checklist", "has_failed", docx.KindBool, "", "Yes when an item of this checklist failed.", "Có khi danh mục này có hạng mục không đạt."},
	{"checklist", "total", docx.KindNumber, "", "Number of items in the checklist.", "Số hạng mục trong danh mục."},
	{"checklist", "passed", docx.KindNumber, "", "Items that passed.", "Số hạng mục đạt."},
	{"checklist", "failed", docx.KindNumber, "", "Items that failed.", "Số hạng mục không đạt."},
	{"checklist", "not_applicable", docx.KindNumber, "", "Items marked not applicable.", "Số hạng mục không áp dụng."},
	{"checklist", "untested", docx.KindNumber, "", "Items without a result.", "Số hạng mục chưa có kết quả."},
	{"checklist", "tested", docx.KindNumber, "", "Items with a result (passed, failed or not applicable).", "Số hạng mục đã có kết quả (đạt, không đạt hoặc không áp dụng)."},
	{"checklist", "coverage", docx.KindNumber, "", "Share of items with a result, in percent, one decimal.", "Tỷ lệ hạng mục đã có kết quả, theo phần trăm, một chữ số thập phân."},
	{"checklist_section", "checklist", docx.KindText, "", "Name of the checklist the section belongs to.", "Tên danh mục chứa mục này."},
	{"checklist_section", "id", docx.KindText, "", "Section ID, such as WSTG-ATHN.", "Mã mục, ví dụ WSTG-ATHN."},
	{"checklist_section", "title", docx.KindText, "", "Section title.", "Tên mục."},
	{"checklist_section", "total", docx.KindNumber, "", "Number of items in the section.", "Số hạng mục trong mục."},
	{"checklist_section", "passed", docx.KindNumber, "", "Items that passed.", "Số hạng mục đạt."},
	{"checklist_section", "failed", docx.KindNumber, "", "Items that failed.", "Số hạng mục không đạt."},
	{"checklist_section", "not_applicable", docx.KindNumber, "", "Items marked not applicable.", "Số hạng mục không áp dụng."},
	{"checklist_section", "untested", docx.KindNumber, "", "Items without a result.", "Số hạng mục chưa có kết quả."},
	{"checklist_section", "tested", docx.KindNumber, "", "Items with a result (passed, failed or not applicable).", "Số hạng mục đã có kết quả (đạt, không đạt hoặc không áp dụng)."},
	{"checklist_section", "coverage", docx.KindNumber, "", "Share of items with a result, in percent, one decimal.", "Tỷ lệ hạng mục đã có kết quả, theo phần trăm, một chữ số thập phân."},
	{"checklist_item", "checklist", docx.KindText, "", "Name of the checklist.", "Tên danh mục kiểm thử."},
	{"checklist_item", "section", docx.KindText, "", "Title of the item's section.", "Tên mục chứa hạng mục."},
	{"checklist_item", "id", docx.KindText, "", "Item ID, such as WSTG-INPV-05.", "Mã hạng mục, ví dụ WSTG-INPV-05."},
	{"checklist_item", "title", docx.KindText, "", "Item title.", "Tên hạng mục."},
	{"checklist_item", "severity", docx.KindText, "", "The item's severity hint; may be empty.", "Mức độ gợi ý của hạng mục; có thể trống."},
	{"checklist_item", "severity_label", docx.KindText, "", "That severity in the template language.", "Mức độ đó theo ngôn ngữ của mẫu."},
}

// labelDescription describes every labels.* field.
var labelDescription = map[string]string{
	"en": "Built-in label in the template language.",
	"vi": "Nhãn dựng sẵn theo ngôn ngữ của mẫu.",
}

// TemplateReference lists every template field with examples from the
// sample data in the template language, and descriptions in locale ("en"
// when unsupported).
func TemplateReference(language, locale string) []TemplateField {
	if !IsTemplateLanguage(language) {
		language = "en"
	}
	if !IsTemplateLanguage(locale) {
		locale = "en"
	}
	data := TemplateData(SampleReportInput(), language)
	out := make([]TemplateField, 0, len(fieldSpecs)+len(templateLabels["en"]))
	for _, f := range fieldSpecs {
		desc := f.en
		if locale == "vi" {
			desc = f.vi
		}
		within := itemGroupList[f.group]
		key := f.path
		if within != "" {
			key = f.group + "." + f.path
		}
		out = append(out, TemplateField{
			Key: key, Path: f.path, Group: f.group, Within: within,
			Type: f.kind, Items: f.items, Description: desc, Example: exampleOf(data, within, f.path), Tag: tagFor(f.path, f.kind),
		})
	}
	for _, k := range labelKeys() {
		out = append(out, TemplateField{
			Key: "labels." + k, Path: "labels." + k, Group: "labels", Type: docx.KindText,
			Description: labelDescription[locale], Example: label(language, k, k), Tag: "{labels." + k + "}",
		})
	}
	return out
}

// labelKeys are the labels.* keys (status labels are not exposed).
func labelKeys() []string {
	keys := make([]string, 0, len(templateLabels["en"]))
	for k := range templateLabels["en"] {
		if !strings.HasPrefix(k, "st_") && !strings.HasPrefix(k, "rt_") {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys
}

// tagFor is the tag to paste for a field.
func tagFor(path string, kind docx.Kind) string {
	switch kind {
	case docx.KindMarkdown:
		return "{@" + path + "}"
	case docx.KindList, docx.KindBool:
		return "{#" + path + "}…{/" + path + "}"
	case docx.KindTextList:
		return "{#" + path + "}{.}{/" + path + "}"
	}
	return "{" + path + "}"
}

const maxExample = 160

// exampleOf is the sample value of a field as text: for an item field, the
// first item that has a value.
func exampleOf(data map[string]any, within, path string) string {
	if within == "" {
		return exampleText(lookupPath(data, path))
	}
	var items []map[string]any
	if v, ok := data[within].([]map[string]any); ok {
		items = v
	}
	for _, it := range items {
		if s := exampleText(it[path]); s != "" && s != "false" {
			return s
		}
	}
	if len(items) > 0 {
		return exampleText(items[0][path])
	}
	return ""
}

func lookupPath(data map[string]any, path string) any {
	var v any = data
	for _, seg := range strings.Split(path, ".") {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[seg]
	}
	return v
}

func exampleText(v any) string {
	var s string
	switch x := v.(type) {
	case []map[string]any:
		return ""
	case []string:
		s = strings.Join(x, " | ")
	case bool:
		if x {
			s = "true"
		} else {
			s = "false"
		}
	default:
		s = docxText(v)
	}
	r := []rune(s)
	if len(r) > maxExample {
		return string(r[:maxExample-1]) + "…"
	}
	return s
}

// docxText renders a scalar the way the renderer prints it.
func docxText(v any) string { return docx.ValueText(v) }

// TemplateSchema is the shape of TemplateData for the static tag checks.
func TemplateSchema() *docx.Schema {
	root := &docx.Schema{Kind: docx.KindObject, Fields: map[string]*docx.Schema{}}
	items := map[string]*docx.Schema{}
	for g := range itemGroupList {
		items[g] = &docx.Schema{Kind: docx.KindObject, Fields: map[string]*docx.Schema{}}
	}
	put := func(into *docx.Schema, path string, s *docx.Schema) {
		segs := strings.Split(path, ".")
		cur := into
		for _, seg := range segs[:len(segs)-1] {
			next, ok := cur.Fields[seg]
			if !ok {
				next = &docx.Schema{Kind: docx.KindObject, Fields: map[string]*docx.Schema{}}
				cur.Fields[seg] = next
			}
			cur = next
		}
		cur.Fields[segs[len(segs)-1]] = s
	}
	for _, f := range fieldSpecs {
		s := &docx.Schema{Kind: f.kind}
		if f.kind == docx.KindList {
			s.Fields = items[f.items].Fields
		}
		if g, isItem := items[f.group]; isItem {
			put(g, f.path, s)
			continue
		}
		put(root, f.path, s)
	}
	for _, k := range labelKeys() {
		put(root, "labels."+k, &docx.Schema{Kind: docx.KindText})
	}
	return root
}

// referenceGroups orders and titles the groups in the Markdown reference.
var referenceGroups = []struct{ id, title string }{
	{"report", "Report"}, {"campaign", "Campaign"}, {"client", "Client"}, {"stats", "Statistics"},
	{"findings", "Finding lists"}, {"finding", "Each finding (inside {#findings}…{/findings} or a findings_by_severity list)"},
	{"retests", "Retests"}, {"retest", "Each retest (inside {#retests}…{/retests})"},
	{"team", "Team"}, {"team_member", "Each team member (inside {#team}…{/team})"},
	{"checklists", "Methodology checklists"}, {"checklist", "Each checklist (inside {#checklists}…{/checklists})"},
	{"checklist_section", "Each checklist section (inside {#checklist_sections}…{/checklist_sections})"},
	{"checklist_item", "Each failed checklist item (inside {#checklist_failed_items}…{/checklist_failed_items})"},
}

// TemplateReferenceMarkdown is the tag reference as Markdown tables (English
// descriptions, examples from the sample data): the data reference section
// of the architecture doc and the published guide are generated from it.
func TemplateReferenceMarkdown() string {
	fields := TemplateReference("en", "en")
	var b strings.Builder
	cell := func(s string) string {
		return strings.NewReplacer("|", `\|`, "\n", " ").Replace(s)
	}
	for _, g := range referenceGroups {
		b.WriteString("### " + g.title + "\n\n| Tag | Type | Description | Example |\n|---|---|---|---|\n")
		for _, f := range fields {
			if f.Group != g.id {
				continue
			}
			ex := f.Example
			if ex != "" {
				ex = "`" + strings.ReplaceAll(cell(ex), "`", "'") + "`"
			}
			b.WriteString("| `" + cell(f.Tag) + "` | " + string(f.Type) + " | " + cell(f.Description) + " | " + ex + " |\n")
		}
		b.WriteString("\n")
	}
	b.WriteString("### Labels\n\nBuilt-in text in the template's language (`{labels.<key>}`); the English text is shown.\n\n| Tag | Text |\n|---|---|\n")
	for _, k := range labelKeys() {
		b.WriteString("| `{labels." + k + "}` | " + cell(label("en", k, k)) + " |\n")
	}
	return b.String()
}
