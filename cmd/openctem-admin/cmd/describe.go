package cmd

import (
	"fmt"
	"strconv"

	"github.com/spf13/cobra"
)

var describeCmd = &cobra.Command{
	Use:   "describe",
	Short: "Show detailed information about a resource",
}

var describeAdminCmd = &cobra.Command{
	Use:   "admin ID",
	Short: "Show details of an admin user",
	Args:  cobra.ExactArgs(1),
	RunE:  runDescribeAdmin,
}

var describeAuditLogCmd = &cobra.Command{
	Use:     "audit-log ID",
	Aliases: []string{"log"},
	Short:   "Show details of an audit log entry",
	Args:    cobra.ExactArgs(1),
	RunE:    runDescribeAuditLog,
}

var describeTargetMappingCmd = &cobra.Command{
	Use:     "target-mapping ID",
	Aliases: []string{"tm"},
	Short:   "Show details of a target mapping",
	Args:    cobra.ExactArgs(1),
	RunE:    runDescribeTargetMapping,
}

func init() {
	describeCmd.AddCommand(describeAdminCmd)
	describeCmd.AddCommand(describeAuditLogCmd)
	describeCmd.AddCommand(describeTargetMappingCmd)
}

func runDescribeAdmin(cmd *cobra.Command, args []string) error {
	client := mustClient()
	data, err := client.Get("/api/v1/admin/admins/" + args[0])
	if err != nil {
		return err
	}

	var resp AdminResponse
	if err := unmarshal(data, &resp); err != nil {
		return err
	}

	switch flagOutput {
	case outputJSON:
		printJSON(resp)
	case outputYAML:
		printYAML(resp)
	default:
		fmt.Printf("ID:          %s\n", resp.ID)
		fmt.Printf("Email:       %s\n", resp.Email)
		fmt.Printf("Name:        %s\n", resp.Name)
		fmt.Printf("Role:        %s\n", resp.Role)
		fmt.Printf("Active:      %s\n", boolToStr(resp.IsActive))
		fmt.Printf("Last Used:   %s\n", ptrStr(resp.LastUsedAt))
		fmt.Printf("Last IP:     %s\n", resp.LastUsedIP)
		fmt.Printf("Created At:  %s\n", resp.CreatedAt)
		fmt.Printf("Updated At:  %s\n", resp.UpdatedAt)
	}
	return nil
}

func runDescribeAuditLog(cmd *cobra.Command, args []string) error {
	client := mustClient()
	data, err := client.Get("/api/v1/admin/audit-logs/" + args[0])
	if err != nil {
		return err
	}

	var resp AuditLogResponse
	if err := unmarshal(data, &resp); err != nil {
		return err
	}

	switch flagOutput {
	case outputJSON:
		printJSON(resp)
	case outputYAML:
		printYAML(resp)
	default:
		fmt.Printf("ID:              %s\n", resp.ID)
		fmt.Printf("Admin ID:        %s\n", ptrStr(resp.AdminID))
		fmt.Printf("Admin Email:     %s\n", resp.AdminEmail)
		fmt.Printf("Action:          %s\n", resp.Action)
		fmt.Printf("Resource Type:   %s\n", resp.ResourceType)
		fmt.Printf("Resource ID:     %s\n", ptrStr(resp.ResourceID))
		fmt.Printf("Resource Name:   %s\n", resp.ResourceName)
		fmt.Printf("Request Method:  %s\n", resp.RequestMethod)
		fmt.Printf("Request Path:    %s\n", resp.RequestPath)
		fmt.Printf("Response Status: %d\n", resp.ResponseStatus)
		fmt.Printf("IP Address:      %s\n", resp.IPAddress)
		fmt.Printf("User Agent:      %s\n", resp.UserAgent)
		fmt.Printf("Success:         %s\n", successStr(resp.Success))
		if resp.ErrorMessage != "" {
			fmt.Printf("Error:           %s\n", resp.ErrorMessage)
		}
		fmt.Printf("Created At:      %s\n", resp.CreatedAt)
	}
	return nil
}

func runDescribeTargetMapping(cmd *cobra.Command, args []string) error {
	client := mustClient()
	data, err := client.Get("/api/v1/admin/target-mappings/" + args[0])
	if err != nil {
		return err
	}

	var resp TargetMappingResponse
	if err := unmarshal(data, &resp); err != nil {
		return err
	}

	switch flagOutput {
	case outputJSON:
		printJSON(resp)
	case outputYAML:
		printYAML(resp)
	default:
		fmt.Printf("ID:           %s\n", resp.ID)
		fmt.Printf("Target Type:  %s\n", resp.TargetType)
		fmt.Printf("Asset Type:   %s\n", resp.AssetType)
		fmt.Printf("Priority:     %s\n", strconv.Itoa(resp.Priority))
		fmt.Printf("Primary:      %s\n", boolToStr(resp.IsPrimary))
		fmt.Printf("Active:       %s\n", boolToStr(resp.IsActive))
		fmt.Printf("Description:  %s\n", ptrStr(resp.Description))
		fmt.Printf("Created By:   %s\n", ptrStr(resp.CreatedBy))
		fmt.Printf("Created At:   %s\n", resp.CreatedAt)
		fmt.Printf("Updated At:   %s\n", resp.UpdatedAt)
	}
	return nil
}
