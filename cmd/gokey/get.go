package main

import (
	"fmt"
	"github.com/spf13/cobra"
	"github.com/zoroqi/gokey"
)

var getCmd = &cobra.Command{
	Use:   "get [path]",
	Short: "Get password",
	Args:  cobra.MinimumNArgs(0),
	RunE:  runGet,
}

func runGet(cmd *cobra.Command, args []string) error {
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
	pw := ""
	if info.Rule == "pw" {
		pw = info.Password
	} else if info.Rule == "hash" {
		chars := gokey.GetCharset(info.Charset)
		if chars == "" {
			return fmt.Errorf("not founc charset")
		}
		hash := gokey.GetHashFunc(info.Hash, nil)
		if hash == nil {
			return fmt.Errorf("not found hash")
		}

		salt, err := promptPw("Enter salt")
		if err != nil {
			return fmt.Errorf("failed to get entry: %w", err)
		}
		pw = gokey.GenerateKey(info.Plaintext, salt, info.Length, chars, hash)
	}
	if writeClipboardFlag {
		writeClipboard(pw)
	} else {
		fmt.Println(pw)
	}
	return nil
}
