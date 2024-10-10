package main

import (
	"encoding/json"
	"fmt"
	"github.com/spf13/cobra"
	"github.com/zoroqi/gokey"
)

var showCmd = &cobra.Command{
	Use:   "show [path]",
	Short: "Show an entry",
	Args:  cobra.MinimumNArgs(1),
	RunE:  runShow,
}

func runShow(cmd *cobra.Command, args []string) error {
	path := args[0]
	if !gokey.ValidatePath(path) {
		return gokey.ErrPath
	}
	db, err := openDatabase()
	if err != nil {
		return err
	}

	info, err := db.GetEntry(path)
	if err != nil {
		return err
	}
	info.Password = ""
	bs, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return err
	}
	fmt.Printf("%s", bs)

	return nil
}
