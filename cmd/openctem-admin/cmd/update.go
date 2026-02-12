package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update a resource",
}

var updateAdminCmd = &cobra.Command{
	Use:   "admin ID",
	Short: "Update an admin user",
	Args:  cobra.ExactArgs(1),
	RunE:  runUpdateAdmin,
}

var updateTargetMappingCmd = &cobra.Command{
	Use:     "target-mapping ID",
	Aliases: []string{"tm"},
	Short:   "Update a target mapping",
	Args:    cobra.ExactArgs(1),
	RunE:    runUpdateTargetMapping,
}

func init() {
	// admin flags
	updateAdminCmd.Flags().String("name", "", "Admin name")
	updateAdminCmd.Flags().String("role", "", "Admin role: super_admin, ops_admin, readonly")
	updateAdminCmd.Flags().Bool("active", true, "Active status")

	// target-mapping flags
	updateTargetMappingCmd.Flags().Int("priority", 0, "Priority")
	updateTargetMappingCmd.Flags().Bool("active", true, "Active status")
	updateTargetMappingCmd.Flags().String("description", "", "Description")

	updateCmd.AddCommand(updateAdminCmd)
	updateCmd.AddCommand(updateTargetMappingCmd)
}

func runUpdateAdmin(cmd *cobra.Command, args []string) error {
	body := make(map[string]any)

	if cmd.Flags().Changed("name") {
		v, _ := cmd.Flags().GetString("name")
		body["name"] = v
	}
	if cmd.Flags().Changed("role") {
		v, _ := cmd.Flags().GetString("role")
		body["role"] = v
	}
	if cmd.Flags().Changed("active") {
		v, _ := cmd.Flags().GetBool("active")
		body["is_active"] = v
	}

	if len(body) == 0 {
		return fmt.Errorf("at least one of --name, --role, or --active must be specified")
	}

	client := mustClient()
	data, err := client.Patch("/api/v1/admin/admins/"+args[0], body)
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
		fmt.Printf("Admin %s updated.\n", resp.ID)
	}
	return nil
}

func runUpdateTargetMapping(cmd *cobra.Command, args []string) error {
	body := make(map[string]any)

	if cmd.Flags().Changed("priority") {
		v, _ := cmd.Flags().GetInt("priority")
		body["priority"] = v
	}
	if cmd.Flags().Changed("active") {
		v, _ := cmd.Flags().GetBool("active")
		body["is_active"] = v
	}
	if cmd.Flags().Changed("description") {
		v, _ := cmd.Flags().GetString("description")
		body["description"] = v
	}

	if len(body) == 0 {
		return fmt.Errorf("at least one of --priority, --active, or --description must be specified")
	}

	client := mustClient()
	data, err := client.Patch("/api/v1/admin/target-mappings/"+args[0], body)
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
		fmt.Printf("Target mapping %s updated.\n", resp.ID)
	}
	return nil
}
