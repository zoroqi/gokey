package main

import (
	"fmt"
	"github.com/spf13/cobra"
)

var lsCmd = &cobra.Command{
	Use:     "ls",
	Short:   "List entries",
	Aliases: []string{"list"},
	RunE:    runLs,
}

func runLs(cmd *cobra.Command, args []string) error {
	db, err := openDatabase()
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	results := db.Search(nil)
	printTable(results)
	return nil
}
