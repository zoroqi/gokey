package main

import "github.com/spf13/cobra"

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Edit configuration",
}

func init() {
	configCmd.AddCommand(changeCmd)

	rootCmd.PreRun = func(cmd *cobra.Command, args []string) {
		if writeClipboardFlag {
			initClipboard()
		}
	}
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
