package cmd

import (
	"fmt"
	"net/url"
	"strconv"

	"github.com/spf13/cobra"
)

var getCmd = &cobra.Command{
	Use:   "get",
	Short: "List resources",
}

var getAdminsCmd = &cobra.Command{
	Use:     "admins",
	Aliases: []string{"admin"},
	Short:   "List admin users",
	RunE:    runGetAdmins,
}

var getAuditLogsCmd = &cobra.Command{
	Use:     "audit-logs",
	Aliases: []string{"audit-log", "logs"},
	Short:   "List audit log entries",
	RunE:    runGetAuditLogs,
}

var getTargetMappingsCmd = &cobra.Command{
	Use:     "target-mappings",
	Aliases: []string{"target-mapping", "tm"},
	Short:   "List target mappings",
	RunE:    runGetTargetMappings,
}

func init() {
	// admins flags
	getAdminsCmd.Flags().String("role", "", "Filter by role (super_admin, ops_admin, readonly)")
	getAdminsCmd.Flags().String("search", "", "Search by email or name")
	getAdminsCmd.Flags().String("active", "", "Filter by active status (true/false)")
	getAdminsCmd.Flags().Int("page", 1, "Page number")
	getAdminsCmd.Flags().Int("per-page", 20, "Items per page")

	// audit-logs flags
	getAuditLogsCmd.Flags().String("action", "", "Filter by action")
	getAuditLogsCmd.Flags().String("resource-type", "", "Filter by resource type")
	getAuditLogsCmd.Flags().String("from", "", "From date (RFC3339)")
	getAuditLogsCmd.Flags().String("to", "", "To date (RFC3339)")
	getAuditLogsCmd.Flags().String("search", "", "Search by email or resource")
	getAuditLogsCmd.Flags().Int("page", 1, "Page number")
	getAuditLogsCmd.Flags().Int("per-page", 20, "Items per page")

	// target-mappings flags
	getTargetMappingsCmd.Flags().String("target-type", "", "Filter by target type")
	getTargetMappingsCmd.Flags().String("asset-type", "", "Filter by asset type")
	getTargetMappingsCmd.Flags().String("active", "", "Filter by active status (true/false)")
	getTargetMappingsCmd.Flags().Int("page", 1, "Page number")
	getTargetMappingsCmd.Flags().Int("per-page", 20, "Items per page")

	getCmd.AddCommand(getAdminsCmd)
	getCmd.AddCommand(getAuditLogsCmd)
	getCmd.AddCommand(getTargetMappingsCmd)
}

func runGetAdmins(cmd *cobra.Command, args []string) error {
	client := mustClient()

	params := url.Values{}
	if v, _ := cmd.Flags().GetString("role"); v != "" {
		params.Set("role", v)
	}
	if v, _ := cmd.Flags().GetString("search"); v != "" {
		params.Set("search", v)
	}
	if v, _ := cmd.Flags().GetString("active"); v != "" {
		params.Set("is_active", v)
	}
	if v, _ := cmd.Flags().GetInt("page"); v > 0 {
		params.Set("page", strconv.Itoa(v))
	}
	if v, _ := cmd.Flags().GetInt("per-page"); v > 0 {
		params.Set("per_page", strconv.Itoa(v))
	}

	path := "/api/v1/admin/admins"
	if q := params.Encode(); q != "" {
		path += "?" + q
	}

	data, err := client.Get(path)
	if err != nil {
		return err
	}

	var resp AdminListResponse
	if err := unmarshal(data, &resp); err != nil {
		return err
	}

	switch flagOutput {
	case outputJSON:
		printJSON(resp)
	case outputYAML:
		printYAML(resp)
	case outputWide:
		t := newTable("ID", "EMAIL", "NAME", "ROLE", "ACTIVE", "LAST USED", "CREATED")
		for _, a := range resp.Data {
			t.AddRow(a.ID, a.Email, a.Name, a.Role, boolToStr(a.IsActive), ptrStr(a.LastUsedAt), shortTime(a.CreatedAt))
		}
		t.Flush()
		printPagination(resp.Total, resp.Page, resp.PerPage, resp.TotalPages)
	default:
		t := newTable("ID", "EMAIL", "ROLE", "ACTIVE")
		for _, a := range resp.Data {
			t.AddRow(truncate(a.ID, 12), a.Email, a.Role, boolToStr(a.IsActive))
		}
		t.Flush()
		printPagination(resp.Total, resp.Page, resp.PerPage, resp.TotalPages)
	}
	return nil
}

func runGetAuditLogs(cmd *cobra.Command, args []string) error {
	client := mustClient()

	params := url.Values{}
	if v, _ := cmd.Flags().GetString("action"); v != "" {
		params.Set("action", v)
	}
	if v, _ := cmd.Flags().GetString("resource-type"); v != "" {
		params.Set("resource_type", v)
	}
	if v, _ := cmd.Flags().GetString("from"); v != "" {
		params.Set("from", v)
	}
	if v, _ := cmd.Flags().GetString("to"); v != "" {
		params.Set("to", v)
	}
	if v, _ := cmd.Flags().GetString("search"); v != "" {
		params.Set("search", v)
	}
	if v, _ := cmd.Flags().GetInt("page"); v > 0 {
		params.Set("page", strconv.Itoa(v))
	}
	if v, _ := cmd.Flags().GetInt("per-page"); v > 0 {
		params.Set("per_page", strconv.Itoa(v))
	}

	path := "/api/v1/admin/audit-logs"
	if q := params.Encode(); q != "" {
		path += "?" + q
	}

	data, err := client.Get(path)
	if err != nil {
		return err
	}

	var resp AuditLogListResponse
	if err := unmarshal(data, &resp); err != nil {
		return err
	}

	switch flagOutput {
	case outputJSON:
		printJSON(resp)
	case outputYAML:
		printYAML(resp)
	case outputWide:
		t := newTable("ID", "ADMIN", "ACTION", "RESOURCE", "METHOD", "STATUS", "OK", "TIME")
		for _, l := range resp.Data {
			t.AddRow(l.ID, l.AdminEmail, l.Action, l.ResourceType,
				l.RequestMethod, fmt.Sprintf("%d", l.ResponseStatus),
				successStr(l.Success), shortTime(l.CreatedAt))
		}
		t.Flush()
		printPagination(resp.Total, resp.Page, resp.PerPage, resp.TotalPages)
	default:
		t := newTable("ID", "ADMIN", "ACTION", "RESOURCE", "OK", "TIME")
		for _, l := range resp.Data {
			t.AddRow(truncate(l.ID, 12), l.AdminEmail, l.Action, l.ResourceType,
				successStr(l.Success), shortTime(l.CreatedAt))
		}
		t.Flush()
		printPagination(resp.Total, resp.Page, resp.PerPage, resp.TotalPages)
	}
	return nil
}

func runGetTargetMappings(cmd *cobra.Command, args []string) error {
	client := mustClient()

	params := url.Values{}
	if v, _ := cmd.Flags().GetString("target-type"); v != "" {
		params.Set("target_type", v)
	}
	if v, _ := cmd.Flags().GetString("asset-type"); v != "" {
		params.Set("asset_type", v)
	}
	if v, _ := cmd.Flags().GetString("active"); v != "" {
		params.Set("is_active", v)
	}
	if v, _ := cmd.Flags().GetInt("page"); v > 0 {
		params.Set("page", strconv.Itoa(v))
	}
	if v, _ := cmd.Flags().GetInt("per-page"); v > 0 {
		params.Set("per_page", strconv.Itoa(v))
	}

	path := "/api/v1/admin/target-mappings"
	if q := params.Encode(); q != "" {
		path += "?" + q
	}

	data, err := client.Get(path)
	if err != nil {
		return err
	}

	var resp TargetMappingListResponse
	if err := unmarshal(data, &resp); err != nil {
		return err
	}

	switch flagOutput {
	case outputJSON:
		printJSON(resp)
	case outputYAML:
		printYAML(resp)
	case outputWide:
		t := newTable("ID", "TARGET TYPE", "ASSET TYPE", "PRIORITY", "PRIMARY", "ACTIVE", "DESCRIPTION", "CREATED")
		for _, m := range resp.Data {
			t.AddRow(m.ID, m.TargetType, m.AssetType, strconv.Itoa(m.Priority), boolToStr(m.IsPrimary), boolToStr(m.IsActive), ptrStr(m.Description), shortTime(m.CreatedAt))
		}
		t.Flush()
		printPagination(resp.Total, resp.Page, resp.PerPage, resp.TotalPages)
	default:
		t := newTable("ID", "TARGET TYPE", "ASSET TYPE", "PRIORITY", "ACTIVE")
		for _, m := range resp.Data {
			t.AddRow(truncate(m.ID, 12), m.TargetType, m.AssetType, strconv.Itoa(m.Priority), boolToStr(m.IsActive))
		}
		t.Flush()
		printPagination(resp.Total, resp.Page, resp.PerPage, resp.TotalPages)
	}
	return nil
}
