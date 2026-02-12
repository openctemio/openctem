package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var deleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete a resource",
}

var deleteAdminCmd = &cobra.Command{
	Use:   "admin ID",
	Short: "Delete an admin user",
	Args:  cobra.ExactArgs(1),
	RunE:  runDeleteAdmin,
}

var deleteTargetMappingCmd = &cobra.Command{
	Use:     "target-mapping ID",
	Aliases: []string{"tm"},
	Short:   "Delete a target mapping",
	Args:    cobra.ExactArgs(1),
	RunE:    runDeleteTargetMapping,
}

func init() {
	deleteCmd.AddCommand(deleteAdminCmd)
	deleteCmd.AddCommand(deleteTargetMappingCmd)
}

func runDeleteAdmin(cmd *cobra.Command, args []string) error {
	client := mustClient()
	if err := client.Delete("/api/v1/admin/admins/" + args[0]); err != nil {
		return err
	}
	fmt.Printf("Admin %s deleted.\n", args[0])
	return nil
}

func runDeleteTargetMapping(cmd *cobra.Command, args []string) error {
	client := mustClient()
	if err := client.Delete("/api/v1/admin/target-mappings/" + args[0]); err != nil {
		return err
	}
	fmt.Printf("Target mapping %s deleted.\n", args[0])
	return nil
}
