package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var rotateKeyCmd = &cobra.Command{
	Use:   "rotate-key",
	Short: "Rotate an API key",
}

var rotateKeyAdminCmd = &cobra.Command{
	Use:   "admin ID",
	Short: "Rotate an admin user's API key",
	Args:  cobra.ExactArgs(1),
	RunE:  runRotateKeyAdmin,
}

var auditStatsCmd = &cobra.Command{
	Use:   "audit-stats",
	Short: "Show audit log statistics",
	RunE:  runAuditStats,
}

func init() {
	rotateKeyCmd.AddCommand(rotateKeyAdminCmd)
}

func runRotateKeyAdmin(cmd *cobra.Command, args []string) error {
	client := mustClient()
	data, err := client.Post("/api/v1/admin/admins/"+args[0]+"/rotate-key", nil)
	if err != nil {
		return err
	}

	var resp AdminRotateKeyResponse
	if err := unmarshal(data, &resp); err != nil {
		return err
	}

	switch flagOutput {
	case outputJSON:
		printJSON(resp)
	case outputYAML:
		printYAML(resp)
	default:
		fmt.Printf("API key rotated for admin %s.\n\n", args[0])
		fmt.Printf("New API Key (save this, it won't be shown again):\n")
		fmt.Printf("  %s\n", resp.APIKey)
	}
	return nil
}

func runAuditStats(cmd *cobra.Command, args []string) error {
	client := mustClient()
	data, err := client.Get("/api/v1/admin/audit-logs/stats")
	if err != nil {
		return err
	}

	var resp AuditStatsResponse
	if err := unmarshal(data, &resp); err != nil {
		return err
	}

	switch flagOutput {
	case outputJSON:
		printJSON(resp)
	case outputYAML:
		printYAML(resp)
	default:
		fmt.Printf("Audit Log Statistics\n")
		fmt.Printf("  Total Entries:    %d\n", resp.Total)
		fmt.Printf("  Failed (24h):     %d\n", resp.Failed24h)
		if len(resp.RecentActions) > 0 {
			fmt.Printf("\nRecent Actions:\n")
			t := newTable("ADMIN", "ACTION", "RESOURCE", "OK", "TIME")
			for _, a := range resp.RecentActions {
				t.AddRow(a.AdminEmail, a.Action, a.ResourceType, successStr(a.Success), shortTime(a.CreatedAt))
			}
			t.Flush()
		}
	}
	return nil
}
