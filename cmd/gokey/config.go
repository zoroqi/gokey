package main

import (
	"fmt"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
	"os"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Edit configuration",
}

func init() {
	configCmd.AddCommand(changeCmd)
	configCmd.AddCommand(showConfigCmd)
	configCmd.AddCommand(editConfigCmd)
	configCmd.AddCommand(deleteConfigCmd)
}

var changeCmd = &cobra.Command{
	Use:   "change",
	Short: "Change database password",
	RunE:  runChange,
}

func runChange(cmd *cobra.Command, args []string) error {
	db, err := openDatabase()
	if err != nil {
		return err
	}

	pw, err := initPassword()
	if err != nil {
		return err
	}

	db.ChangePassword(pw)

	if err := db.Save(dbFile); err != nil {
		return err
	}

	return nil
}

var showConfigCmd = &cobra.Command{
	Use:   "show",
	Short: "Show configuration",
	RunE:  showConfigRun,
}

func showConfigRun(cmd *cobra.Command, args []string) error {
	db, err := openDatabase()
	if err != nil {
		return err
	}
	table := tablewriter.NewWriter(os.Stdout)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetAutoMergeCells(true)
	table.SetColWidth(200)
	table.SetHeader([]string{"Config", "Key", "Value"})
	table.SetColumnColor(tablewriter.Colors{},
		tablewriter.Colors{},
		tablewriter.Colors{tablewriter.BgCyanColor, tablewriter.FgRedColor})
	if len(args) == 0 {
		// show all
		all, err := db.GetAllConfig()
		if err != nil {
			return err
		}
		for key, config := range all {
			for _, c := range config {
				ss := []string{key, c.K, c.V}
				table.Append(ss)
			}
		}
	} else {
		// show all
		config, err := db.GetConfig(args[0])
		if err != nil {
			return err
		}
		for _, c := range config {
			ss := []string{args[0], c.K, c.V}
			table.Append(ss)
		}
	}
	table.Render()

	return nil
}

var editConfigCmd = &cobra.Command{
	Use:   "edit",
	Short: "insert/update configuration",
	RunE:  editConfigRun,
}

func editConfigRun(cmd *cobra.Command, args []string) error {
	db, err := openDatabase()
	if err != nil {
		return err
	}

	config, err := promptString("Enter config", "")
	if err != nil {
		return err
	}
	if config == "" {
		return fmt.Errorf("config cannot be empty")
	}
	key, err := promptString("Enter key", "")
	if err != nil {
		return err
	}
	if key == "" {
		return fmt.Errorf("key cannot be empty")
	}
	value, err := promptString("Enter value", "")
	if err != nil {
		return err
	}
	if value == "" {
		return fmt.Errorf("value cannot be empty")
	}
	err = db.EditConfig(config, key, value)
	if err != nil {
		return err
	}
	if err := db.Save(dbFile); err != nil {
		return err
	}

	return nil
}

var deleteConfigCmd = &cobra.Command{
	Use:   "del",
	Short: "delete configuration",
	RunE:  deleteConfigRun,
}

func deleteConfigRun(cmd *cobra.Command, args []string) error {
	db, err := openDatabase()
	if err != nil {
		return err
	}
	config, err := promptString("Enter config", "")
	if err != nil {
		return err
	}
	if config == "" {
		return fmt.Errorf("config cannot be empty")
	}
	key, err := promptString("Enter key", "")
	if err != nil {
		return err
	}
	if key == "" {
		return fmt.Errorf("key cannot be empty")
	}
	err = db.DelConfig(config, key)
	if err != nil {
		return err
	}
	if err := db.Save(dbFile); err != nil {
		return err
	}

	return nil
}
