package main

import (
	"fmt"
	"github.com/spf13/cobra"
)

var queryCmd = &cobra.Command{
	Use:   "query",
	Short: "Query for entries",
	RunE:  runQuery,
}

func runQuery(cmd *cobra.Command, args []string) error {
	db, err := openDatabase()
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	results := db.Search(args)
	printTable(results)
	return nil
}
