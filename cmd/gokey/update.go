package main

import (
	"fmt"
	"github.com/spf13/cobra"
	"github.com/zoroqi/gokey"
)

var updateCmd = &cobra.Command{
	Use:   "update [path]",
	Short: "Update an existing entry",
	Args:  cobra.MinimumNArgs(1),
	RunE:  runUpdate,
}

func runUpdate(cmd *cobra.Command, args []string) error {
	path := args[0]
	if !gokey.ValidatePath(path) {
		return gokey.ErrPath
	}
	db, err := openDatabase()
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	info, err := db.GetEntry(path)
	if err != nil {
		return fmt.Errorf("failed to get entry: %w", err)
	}

	info, err = readInfo(info, db.GetCharsets(), gokey.GetAllHashName())
	if err != nil {
		return err
	}

	if err := db.UpdateEntry(path, info); err != nil {
		return fmt.Errorf("failed to update entry: %w", err)
	}

	if err := db.Save(dbFile); err != nil {
		return fmt.Errorf("failed to save database: %w", err)
	}

	fmt.Println("Entry updated successfully")
	return nil
}
