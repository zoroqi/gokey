package main

import (
	"fmt"
	"github.com/spf13/cobra"
	"github.com/zoroqi/gokey"
	"time"
)

var generate_flag_chars string
var generate_flag_len int
var generate_flag_salt string
var generate_flag_plaintext string
var generate_flag_hash string

var generateCmd = &cobra.Command{
	Use:     "generate",
	Aliases: []string{"pw"},
	Short:   "Generate random password",
	RunE:    runGenerate,
}

func init() {
	generateCmd.Flags().StringVar(&generate_flag_chars, "chars", "default", gokey.CharsHelpString())
	generateCmd.Flags().IntVarP(&generate_flag_len, "len", "l", 20, "password length")
	generateCmd.Flags().StringVar(&generate_flag_salt, "salt", "", "salt, default: unix micro timestamp")
	generateCmd.Flags().StringVar(&generate_flag_plaintext, "text", "", "plaintext, default: unix micro timestamp")
	generateCmd.Flags().StringVar(&generate_flag_hash, "hash", "SHA512", gokey.HashHelpString())
}

func runGenerate(cmd *cobra.Command, args []string) error {
	if generate_flag_salt == "" {
		generate_flag_salt = fmt.Sprintf("%d", time.Now().UnixMicro())
	}
	if generate_flag_plaintext == "" {
		generate_flag_plaintext = fmt.Sprintf("%d", time.Now().UnixMicro())
	}
	pw := gokey.GenerateKey(generate_flag_plaintext, generate_flag_salt, generate_flag_len,
		gokey.GetCharset(generate_flag_chars), gokey.GetHashFunc(generate_flag_hash, nil))
	fmt.Println(pw)
	if writeClipboardFlag {
		writeClipboard(pw)
	}
	return nil
}
