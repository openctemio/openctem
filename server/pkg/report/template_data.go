package report

import (
	"strconv"
	"strings"
	"time"
)

// Template data model: the values an organization's report template can
// read (api/docs/architecture/pentest-report-templates.md lists every key).
// It is built only from a ReportInput, which holds one campaign of one
// tenant, so a template can never reach other data.

// TemplateLanguages are the languages a report template can declare; they
// choose the built-in labels (severity, status, headings).
var TemplateLanguages = []string{"en", "vi"}

// IsTemplateLanguage reports whether lang is a supported template language.
func IsTemplateLanguage(lang string) bool {
	for _, l := range TemplateLanguages {
		if l == lang {
			return true
		}
	}
	return false
}

var templateLabels = map[string]map[string]string{
	"en": {
		"summary": "Summary", "findings": "Findings", "severity": "Severity", "count": "Count", "total": "Total",
		"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Info",
		"title": "Title", "status": "Status", "no_findings": "No findings were reported.",
		"affected_targets": "Affected targets", "description": "Description", "steps": "Steps to reproduce",
		"poc": "Proof of concept", "business_impact": "Business impact", "technical_impact": "Technical impact",
		"remediation": "Remediation", "references": "References", "retests": "Retest results",
		"finding": "Finding", "result": "Result", "tested_at": "Tested", "notes": "Notes",
		"generated_at": "Generated", "classification": "Classification",
		"public": "Public", "internal": "Internal use only", "confidential": "Confidential", "restricted": "Restricted",
		"executive_summary": "Executive summary", "technical_report": "Technical report", "finding_report": "Findings report",
		"compliance_report": "Compliance report", "remediation_report": "Remediation report", "retest_report": "Retest report",
		"contents": "Contents", "overview": "Overview", "appendix": "Appendix", "methodology": "Methodology",
		"team": "Team", "name": "Name", "role": "Role", "client": "Client", "contact": "Contact",
		"period": "Testing period", "prepared_for": "Prepared for", "key_findings": "Key findings",
		"no_key_findings": "No critical or high severity findings were reported.", "remediation_plan": "Remediation plan",
		"details": "Details", "reported": "Reported", "cvss": "CVSS", "severity_ratings": "Severity ratings",
		"critical_desc": "Easily exploited; leads to full compromise of the system or its data. Fix immediately.",
		"high_desc":     "Exploitable with moderate effort; significant impact on confidentiality, integrity or availability. Fix as a priority.",
		"medium_desc":   "Exploitable under specific conditions or with limited impact. Fix in the normal release cycle.",
		"low_desc":      "Minor impact or hard to exploit. Fix when convenient.",
		"info_desc":     "No direct risk; a hardening recommendation or an observation.",
		"st_new":        "New", "st_confirmed": "Confirmed", "st_in_progress": "In progress", "st_fix_applied": "Fix applied",
		"st_resolved": "Resolved", "st_false_positive": "False positive", "st_accepted": "Accepted", "st_duplicate": "Duplicate",
		"st_draft": "Draft", "st_in_review": "In review",
		"rt_passed": "Passed", "rt_failed": "Failed", "rt_partial": "Partially fixed", "rt_pending": "Pending",
		"rt_in_progress": "In progress", "rt_canceled": "Canceled", "rt_inconclusive": "Unable to verify",
		"cs_planning": "Planning", "cs_in_progress": "Testing", "cs_reporting": "Reporting", "cs_completed": "Remediation",
		"cs_on_hold": "On hold", "cs_canceled": "Canceled", "cs_archived": "Closed",
		"methodology_coverage": "Methodology coverage", "checklist": "Checklist", "section": "Section", "coverage": "Coverage",
		"passed": "Passed", "failed": "Failed", "not_applicable": "Not applicable", "untested": "Untested", "tested": "Tested",
		"failed_checks": "Failed checks",
	},
	"vi": {
		"summary": "Tóm tắt", "findings": "Phát hiện", "severity": "Mức độ", "count": "Số lượng", "total": "Tổng",
		"critical": "Nghiêm trọng", "high": "Cao", "medium": "Trung bình", "low": "Thấp", "info": "Thông tin",
		"title": "Tiêu đề", "status": "Trạng thái", "no_findings": "Không có phát hiện nào.",
		"affected_targets": "Mục tiêu bị ảnh hưởng", "description": "Mô tả", "steps": "Các bước tái hiện",
		"poc": "Bằng chứng khai thác", "business_impact": "Ảnh hưởng nghiệp vụ", "technical_impact": "Ảnh hưởng kỹ thuật",
		"remediation": "Khắc phục", "references": "Tham khảo", "retests": "Kết quả kiểm tra lại",
		"finding": "Phát hiện", "result": "Kết quả", "tested_at": "Ngày kiểm tra", "notes": "Ghi chú",
		"generated_at": "Ngày tạo", "classification": "Phân loại",
		"public": "Công khai", "internal": "Chỉ dùng nội bộ", "confidential": "Mật", "restricted": "Hạn chế",
		"executive_summary": "Tóm tắt cho lãnh đạo", "technical_report": "Báo cáo kỹ thuật", "finding_report": "Báo cáo phát hiện",
		"compliance_report": "Báo cáo tuân thủ", "remediation_report": "Báo cáo khắc phục", "retest_report": "Báo cáo kiểm tra lại",
		"contents": "Mục lục", "overview": "Tổng quan", "appendix": "Phụ lục", "methodology": "Phương pháp",
		"team": "Nhóm thực hiện", "name": "Họ tên", "role": "Vai trò", "client": "Khách hàng", "contact": "Liên hệ",
		"period": "Thời gian kiểm thử", "prepared_for": "Chuẩn bị cho", "key_findings": "Phát hiện chính",
		"no_key_findings": "Không có phát hiện mức nghiêm trọng hoặc cao.", "remediation_plan": "Kế hoạch khắc phục",
		"details": "Chi tiết", "reported": "Ngày ghi nhận", "cvss": "CVSS", "severity_ratings": "Thang mức độ",
		"critical_desc": "Dễ khai thác; dẫn tới chiếm quyền toàn bộ hệ thống hoặc dữ liệu. Cần khắc phục ngay.",
		"high_desc":     "Khai thác được với nỗ lực vừa phải; ảnh hưởng lớn tới tính bí mật, toàn vẹn hoặc sẵn sàng. Ưu tiên khắc phục.",
		"medium_desc":   "Khai thác được trong điều kiện nhất định hoặc ảnh hưởng hạn chế. Khắc phục trong chu kỳ phát hành thông thường.",
		"low_desc":      "Ảnh hưởng nhỏ hoặc khó khai thác. Khắc phục khi thuận tiện.",
		"info_desc":     "Không có rủi ro trực tiếp; khuyến nghị tăng cường hoặc ghi nhận.",
		"st_new":        "Mới", "st_confirmed": "Đã xác nhận", "st_in_progress": "Đang xử lý", "st_fix_applied": "Đã sửa",
		"st_resolved": "Đã khắc phục", "st_false_positive": "Dương tính giả", "st_accepted": "Chấp nhận rủi ro", "st_duplicate": "Trùng lặp",
		"st_draft": "Bản nháp", "st_in_review": "Đang rà soát",
		"rt_passed": "Đạt", "rt_failed": "Không đạt", "rt_partial": "Khắc phục một phần", "rt_pending": "Đang chờ",
		"rt_in_progress": "Đang kiểm tra", "rt_canceled": "Đã hủy", "rt_inconclusive": "Không thể xác minh",
		"cs_planning": "Lập kế hoạch", "cs_in_progress": "Kiểm thử", "cs_reporting": "Lập báo cáo", "cs_completed": "Khắc phục",
		"cs_on_hold": "Tạm dừng", "cs_canceled": "Đã hủy", "cs_archived": "Đã đóng",
		"methodology_coverage": "Mức độ bao phủ phương pháp kiểm thử", "checklist": "Danh mục kiểm thử", "section": "Mục", "coverage": "Độ bao phủ",
		"passed": "Đạt", "failed": "Không đạt", "not_applicable": "Không áp dụng", "untested": "Chưa kiểm thử", "tested": "Đã kiểm thử",
		"failed_checks": "Hạng mục không đạt",
	},
}

func label(lang, key, fallback string) string {
	if l, ok := templateLabels[lang][key]; ok {
		return l
	}
	if l, ok := templateLabels["en"][key]; ok {
		return l
	}
	return fallback
}

// TemplateData builds the template data map for a report in the given
// template language ("en" when unsupported).
func TemplateData(in ReportInput, lang string) map[string]any {
	if !IsTemplateLanguage(lang) {
		lang = "en"
	}
	labels := map[string]any{}
	for k, v := range templateLabels[lang] {
		if !strings.HasPrefix(k, "st_") && !strings.HasPrefix(k, "rt_") {
			labels[k] = v
		}
	}

	findings := make([]map[string]any, 0, len(in.Findings))
	bySeverity := map[string][]map[string]any{}
	for i, f := range in.Findings {
		number := f.Number
		if number == "" {
			number = strconv.Itoa(i + 1)
		}
		cvss := ""
		if f.CVSSScore > 0 {
			cvss = strconv.FormatFloat(f.CVSSScore, 'f', 1, 64)
		}
		poc := ""
		if in.IncludePOC {
			poc = f.POC
		}
		m := map[string]any{
			"number": number, "title": f.Title,
			"severity": f.Severity, "severity_label": label(lang, f.Severity, f.Severity),
			"status": f.Status, "status_label": label(lang, "st_"+f.Status, f.Status),
			"cvss_score": cvss, "cvss_vector": f.CVSSVector,
			"cwe": f.CWE, "cve": f.CVE, "owasp": f.OWASP,
			"description": f.Description, "business_impact": f.Impact, "technical_impact": f.TechImpact,
			"remediation": f.Remediation, "poc": poc,
			"steps": nonNil(f.Steps), "targets": nonNil(f.Targets), "references": nonNil(f.References),
			"has_steps": len(f.Steps) > 0, "has_targets": len(f.Targets) > 0, "has_references": len(f.References) > 0,
			"is_critical": f.Severity == "critical", "is_high": f.Severity == "high", "is_medium": f.Severity == "medium",
			"is_low": f.Severity == "low", "is_info": f.Severity == "info" || f.Severity == "none",
			"created_at": formatDay(f.CreatedAt),
		}
		findings = append(findings, m)
		bySeverity[f.Severity] = append(bySeverity[f.Severity], m)
	}
	severityGroups := map[string]any{}
	for _, s := range []string{"critical", "high", "medium", "low", "info"} {
		severityGroups[s] = nonNilMaps(bySeverity[s])
	}

	retests := make([]map[string]any, 0, len(in.Retests))
	for _, r := range in.Retests {
		retests = append(retests, map[string]any{
			"finding_title": r.FindingTitle, "finding_severity": r.FindingSeverity,
			"finding_severity_label": label(lang, r.FindingSeverity, r.FindingSeverity),
			"status":                 r.Status, "status_label": label(lang, "rt_"+r.Status, r.Status),
			"notes": r.Notes, "tested_at": r.TestedAt, "environment": r.Environment,
		})
	}

	team := make([]map[string]any, 0, len(in.Campaign.Team))
	for _, m := range in.Campaign.Team {
		team = append(team, map[string]any{"name": m.Name, "role": m.Role})
	}

	out := map[string]any{
		"report": map[string]any{
			"title":                label(lang, in.ReportType, in.TypeLabel()),
			"type":                 in.ReportType,
			"language":             lang,
			"generated_at":         formatDay(in.GeneratedAt),
			"classification":       in.Classification,
			"classification_label": label(lang, in.Classification, in.Classification),
			"watermark":            in.Watermark,
		},
		"campaign": map[string]any{
			"name": in.Campaign.Name, "description": in.Campaign.Description,
			"type": in.Campaign.Type, "status": in.Campaign.Status,
			"status_label": label(lang, "cs_"+in.Campaign.Status, in.Campaign.Status),
			"targets":      in.Campaign.Targets, "approach": in.Campaign.Approach,
			"environment": in.Campaign.Environment, "tlp": in.Campaign.TLP,
			"methodology": in.Campaign.Methodology,
			"start_date":  in.Campaign.StartDate, "end_date": in.Campaign.EndDate,
		},
		"client": map[string]any{"name": in.Campaign.ClientName, "contact": in.Campaign.ClientContact},
		"team":   team,
		"stats": map[string]any{
			"total": in.Stats.Total, "critical": in.Stats.Critical, "high": in.Stats.High,
			"medium": in.Stats.Medium, "low": in.Stats.Low, "info": in.Stats.Info,
			"avg_cvss": in.Stats.AvgCVSS, "max_cvss": in.Stats.MaxCVSS,
			"has_critical": in.Stats.Critical > 0, "has_high": in.Stats.High > 0,
		},
		"findings":             findings,
		"findings_by_severity": severityGroups,
		"has_findings":         len(findings) > 0,
		"retests":              retests,
		"has_retests":          len(retests) > 0,
		"labels":               labels,
	}
	for k, v := range checklistTemplateData(in, lang) {
		out[k] = v
	}
	return out
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func nonNilMaps(s []map[string]any) []map[string]any {
	if s == nil {
		return []map[string]any{}
	}
	return s
}

func formatDay(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format("2006-01-02")
}

// SampleReportInput is fictional report data for previewing a template
// without touching any campaign.
func SampleReportInput() ReportInput {
	created := time.Date(2026, 1, 15, 9, 0, 0, 0, time.UTC)
	return ReportInput{
		Campaign: CampaignData{
			Name:        "Example Corp external assessment",
			Description: "External black-box assessment of the **customer portal** and its API.",
			ClientName:  "Example Corp", ClientContact: "security@example.com",
			Type: "Web application, API", Targets: []string{"web_app", "api"}, Approach: "grey_box", Environment: "staging", TLP: "amber", Status: "completed",
			StartDate: "2026-01-12", EndDate: "2026-01-23", Methodology: "OWASP WSTG",
			Team: []TeamMemberData{{Name: "Alex Tester", Role: "lead"}, {Name: "Sam Reviewer", Role: "reviewer"}},
		},
		Findings: []FindingData{
			{
				Title: "SQL injection in the login form", Severity: "critical", Status: "confirmed",
				CVSSScore: 9.8, CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", CWE: "CWE-89", OWASP: "A03:2021",
				Description: "The `username` parameter is concatenated into a SQL query.\n\nAn attacker can read every table.",
				Steps:       []string{"Open https://portal.example.com/login", "Enter `' OR 1=1 --` as the username", "Observe the admin dashboard"},
				POC:         "POST /login HTTP/1.1\nHost: portal.example.com\n\nusername=' OR 1=1 --&password=x",
				Impact:      "Full read access to customer records.", Remediation: "Use parameterized queries.\n\n- Bind every parameter\n- Add a WAF rule as a stopgap",
				References: []string{"https://owasp.org/www-community/attacks/SQL_Injection"}, Targets: []string{"portal.example.com"},
				CreatedAt: created,
			},
			{
				Title: "Missing rate limit on password reset", Severity: "medium", Status: "fix_applied",
				CVSSScore: 5.3, CWE: "CWE-307", Description: "Password reset requests are not rate limited.",
				Remediation: "Limit requests per account and per IP address.", Targets: []string{"api.example.com"}, CreatedAt: created,
			},
			{
				Title: "Server version disclosed", Severity: "info", Status: "resolved",
				Description: "The `Server` header names the web server version.", Remediation: "Remove the version from the header.",
				CreatedAt: created,
			},
		},
		Checklists:     sampleChecklists(),
		Retests:        []RetestData{{FindingTitle: "Server version disclosed", FindingSeverity: "info", Status: "passed", Notes: "Header removed.", Environment: "staging", TestedAt: "2026-02-02"}},
		Stats:          StatsData{Total: 3, Critical: 1, Medium: 1, Info: 1, AvgCVSS: 7.6, MaxCVSS: 9.8},
		GeneratedAt:    time.Date(2026, 2, 3, 10, 0, 0, 0, time.UTC),
		Classification: "confidential",
		ReportType:     TypeTechnical,
		IncludePOC:     true,
	}
}
