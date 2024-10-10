package main

import (
	"fmt"
	"github.com/spf13/cobra"
	"github.com/zoroqi/gokey"
)

var createCmd = &cobra.Command{
	Use:   "create [path]",
	Short: "Create a new entry",
	Args:  cobra.MinimumNArgs(1),
	RunE:  runCreate,
}

func init() {
	//createCmd.ValidArgs = []string{"path"}
}

func runCreate(cmd *cobra.Command, args []string) (err error) {
	path := args[0]
	if !gokey.ValidatePath(path) {
		return gokey.ErrPath
	}
	db, err := openDatabase()
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	info, err := readInfo(gokey.EntryInfo{}, db.GetCharsets(), gokey.GetAllHashName())
	if err != nil {
		return err
	}

	if err := db.CreateEntry(path, info); err != nil {
		return fmt.Errorf("failed to create entry: %w", err)
	}
	if err := db.Save(dbFile); err != nil {
		return fmt.Errorf("failed to save database: %w", err)
	}
	fmt.Println("Entry created successfully")
	return err
}
