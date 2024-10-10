package main

import (
	"fmt"
	"github.com/zoroqi/gokey"

	"github.com/spf13/cobra"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize a new database",
	RunE:  runInit,
}

func runInit(cmd *cobra.Command, args []string) error {
	if dbFile == "" {
		return fmt.Errorf("database file not specified")
	}
	pw, err := initPassword()
	if err != nil {
		return err
	}
	db, err := gokey.NewDB(pw)
	if err != nil {
		return err
	}

	if err := db.Save(dbFile); err != nil {
		return err
	}

	fmt.Println("Database initialized successfully")
	return nil
}
