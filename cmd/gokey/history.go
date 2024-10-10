package main

import (
	"github.com/spf13/cobra"
	"github.com/zoroqi/gokey"
)

// 添加新的 historyCmd
var historyCmd = &cobra.Command{
	Use:   "history [path]",
	Short: "Show the history of an entry",
	Args:  cobra.MinimumNArgs(1),
	RunE:  runHistory,
}

func runHistory(cmd *cobra.Command, args []string) error {
	path := args[0]
	if !gokey.ValidatePath(path) {
		return gokey.ErrPath
	}
	db, err := openDatabase()
	if err != nil {
		return err
	}

	history, err := db.ExportEntryHistory(path)
	if err != nil {
		return err
	}

	printTable(history)
	return nil
}
