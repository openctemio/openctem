package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var createCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a resource",
}

var createAdminCmd = &cobra.Command{
	Use:   "admin",
	Short: "Create a new admin user",
	RunE:  runCreateAdmin,
}

var createTargetMappingCmd = &cobra.Command{
	Use:     "target-mapping",
	Aliases: []string{"tm"},
	Short:   "Create a new target mapping",
	RunE:    runCreateTargetMapping,
}

func init() {
	// admin flags
	createAdminCmd.Flags().String("email", "", "Admin email (required)")
	createAdminCmd.Flags().String("name", "", "Admin name")
	createAdminCmd.Flags().String("role", "readonly", "Admin role: super_admin, ops_admin, readonly")

	// target-mapping flags
	createTargetMappingCmd.Flags().String("target-type", "", "Target type (required)")
	createTargetMappingCmd.Flags().String("asset-type", "", "Asset type (required)")
	createTargetMappingCmd.Flags().Int("priority", 0, "Priority (lower = higher priority)")
	createTargetMappingCmd.Flags().String("description", "", "Description")

	createCmd.AddCommand(createAdminCmd)
	createCmd.AddCommand(createTargetMappingCmd)
}

func runCreateAdmin(cmd *cobra.Command, args []string) error {
	email, _ := cmd.Flags().GetString("email")
	name, _ := cmd.Flags().GetString("name")
	role, _ := cmd.Flags().GetString("role")

	if email == "" {
		return fmt.Errorf("--email is required")
	}

	body := map[string]string{
		"email": email,
		"role":  role,
	}
	if name != "" {
		body["name"] = name
	}

	client := mustClient()
	data, err := client.Post("/api/v1/admin/admins", body)
	if err != nil {
		return err
	}

	var resp AdminCreateResponse
	if err := unmarshal(data, &resp); err != nil {
		return err
	}

	switch flagOutput {
	case outputJSON:
		printJSON(resp)
	case outputYAML:
		printYAML(resp)
	default:
		fmt.Printf("Admin created successfully.\n\n")
		fmt.Printf("  ID:    %s\n", resp.Admin.ID)
		fmt.Printf("  Email: %s\n", resp.Admin.Email)
		fmt.Printf("  Name:  %s\n", resp.Admin.Name)
		fmt.Printf("  Role:  %s\n", resp.Admin.Role)
		fmt.Printf("\nAPI Key (save this, it won't be shown again):\n")
		fmt.Printf("  %s\n", resp.APIKey)
	}
	return nil
}

func runCreateTargetMapping(cmd *cobra.Command, args []string) error {
	targetType, _ := cmd.Flags().GetString("target-type")
	assetType, _ := cmd.Flags().GetString("asset-type")
	priority, _ := cmd.Flags().GetInt("priority")
	description, _ := cmd.Flags().GetString("description")

	if targetType == "" {
		return fmt.Errorf("--target-type is required")
	}
	if assetType == "" {
		return fmt.Errorf("--asset-type is required")
	}

	body := map[string]any{
		"target_type": targetType,
		"asset_type":  assetType,
	}
	if cmd.Flags().Changed("priority") {
		body["priority"] = priority
	}
	if description != "" {
		body["description"] = description
	}

	client := mustClient()
	data, err := client.Post("/api/v1/admin/target-mappings", body)
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
		fmt.Printf("Target mapping created.\n")
		fmt.Printf("  ID:          %s\n", resp.ID)
		fmt.Printf("  Target Type: %s\n", resp.TargetType)
		fmt.Printf("  Asset Type:  %s\n", resp.AssetType)
		fmt.Printf("  Priority:    %d\n", resp.Priority)
	}
	return nil
}
