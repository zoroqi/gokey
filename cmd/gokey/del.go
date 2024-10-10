package main

import (
	"fmt"
	"github.com/zoroqi/gokey"

	"github.com/spf13/cobra"
)

var delCmd = &cobra.Command{
	Use:   "del [path]",
	Short: "Delete an entry",
	Args:  cobra.MinimumNArgs(1),
	RunE:  runDelete,
}

func runDelete(cmd *cobra.Command, args []string) error {
	path := args[0]
	if !gokey.ValidatePath(path) {
		return gokey.ErrPath
	}
	db, err := openDatabase()
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	if err := db.DeleteEntry(path); err != nil {
		return fmt.Errorf("failed to delete entry: %w", err)
	}

	if err := db.Save(dbFile); err != nil {
		return fmt.Errorf("failed to save database: %w", err)
	}

	fmt.Println("Entry deleted successfully")
	return nil
}
