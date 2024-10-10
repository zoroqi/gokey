package main

import (
	"fmt"
	"github.com/manifoldco/promptui"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
	"github.com/zoroqi/gokey"
	"golang.design/x/clipboard"
	"os"
	"strconv"
	"strings"
	"time"
)

var dbFile string
var writeClipboardFlag bool

var rootCmd = &cobra.Command{
	Use:   "gokey",
	Short: "Gokey is a password manager",
	Long:  `A password manager built with Go, using KeePass database format.`,
}

func init() {
	rootCmd.PersistentFlags().StringVar(&dbFile, "db", "", "database file path")
	rootCmd.PersistentFlags().BoolVarP(&writeClipboardFlag, "clipboard", "c", false, "write password to clipboard")
	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(createCmd)
	rootCmd.AddCommand(queryCmd)
	rootCmd.AddCommand(updateCmd)
	rootCmd.AddCommand(delCmd)
	rootCmd.AddCommand(getCmd)
	rootCmd.AddCommand(lsCmd)
	rootCmd.AddCommand(generateCmd)
	rootCmd.AddCommand(historyCmd)
	rootCmd.AddCommand(configCmd)
	rootCmd.AddCommand(showCmd)
	rootCmd.PreRun = func(cmd *cobra.Command, args []string) {
		if writeClipboardFlag {
			initClipboard()
		}
	}
}

func promptString(label string, defaultValue string) (string, error) {
	prompt := promptui.Prompt{
		Label:     label,
		Default:   defaultValue,
		AllowEdit: true,
	}

	result, err := prompt.Run()
	if err != nil {
		return "", fmt.Errorf("prompt failed: %w", err)
	}

	return result, nil
}

func promptPw(label string) (string, error) {
	prompt := promptui.Prompt{
		Label: label,
		Mask:  ' ',
	}

	result, err := prompt.Run()
	if err != nil {
		return "", fmt.Errorf("prompt failed: %w", err)
	}

	return result, nil
}

func promptInt(label string, defaultValue int) (int, error) {
	dv := strconv.Itoa(defaultValue)
	if dv == "0" {
		dv = ""
	}
	prompt := promptui.Prompt{
		Label:     label,
		Default:   dv,
		AllowEdit: true,
		Validate: func(s string) error {
			_, err := strconv.Atoi(s)
			return err
		},
	}

	result, err := prompt.Run()
	if err != nil {
		return 0, err
	}
	n, _ := strconv.Atoi(result)
	return n, nil
}

func selectString(label string, items []string) (string, error) {
	prompt := promptui.Select{
		Label: label,
		Items: items,
	}

	_, result, err := prompt.Run()
	if err != nil {
		return "", fmt.Errorf("selection failed: %w", err)
	}

	return result, nil
}

func initPassword() (string, error) {
	first, err := promptPw("Enter new database password")
	if err != nil {
		return "", err
	}
	for len(first) < 6 {
		return "", fmt.Errorf("password length must be greater than 6")
	}
	second, err := promptPw("Enter the same password")
	if err != nil {
		return "", err
	}
	if first != second {
		return "", fmt.Errorf("passwords do not match")
	}
	return first, nil
}

func openDatabase() (*gokey.DB, error) {
	if dbFile == "" {
		return nil, fmt.Errorf("database file not specified")
	}
	prompt := promptui.Prompt{
		Label: "Enter database password",
		Mask:  ' ',
	}

	password, err := prompt.Run()
	if err != nil {
		return nil, fmt.Errorf("prompt failed: %w", err)
	}
	return gokey.Open(dbFile, password)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func readInfo(info gokey.EntryInfo, charset []string, hash []string) (gokey.EntryInfo, error) {
	username, err := promptString("Enter username", info.UserName)
	if err != nil {
		return info, err
	}

	note, err := promptString("Enter note", info.Notes)
	if err != nil {
		return info, err
	}

	tags, err := promptString("Enter tags (comma-separated)", strings.Join(info.Tag, ","))
	if err != nil {
		return info, err
	}
	url, err := promptString("Enter url", info.URL)
	if err != nil {
		return info, err
	}
	info.UserName = username
	info.Notes = note
	info.URL = url
	info.Tag = gokey.SplitAndFilterTags(tags)
	rule, err := selectString("Select rule", []string{"pw", "hash"})
	if err != nil {
		return info, err
	}
	info.Rule = rule
	if rule == "pw" {
		if info.Password == "" {
			info.Password = gokey.RandomKey(20, "")
		}
		info.Password, err = promptString("Enter password", info.Password)
		if err != nil {
			return info, err
		}
		info.Plaintext = ""
		info.Hash = ""
		info.Charset = ""
		info.Length = 0
	} else {
		info.Plaintext, err = promptString("Enter plaintext", "")
		if err != nil {
			return info, err
		}
		if info.Plaintext == "" {
			return info, fmt.Errorf("plaintext cannot be empty")
		}
		info.Hash, err = selectString("Select HashFunc", hash)
		if err != nil {
			return info, err
		}

		info.Charset, err = selectString("Select Charset", charset)
		if err != nil {
			return info, err
		}
		for {
			info.Length, err = promptInt("Enter password (no less than 6)", info.Length)
			if err != nil {
				return info, fmt.Errorf("invalid length: %w", err)
			}
			if info.Length < 6 {
				continue
			}
			break
		}
		info.Password = ""
	}
	return info, nil
}

func printTable(entries []gokey.EntryInfo) {

	table := tablewriter.NewWriter(os.Stdout)
	table.SetAlignment(tablewriter.ALIGN_DEFAULT)
	table.SetColWidth(25)
	table.SetHeader([]string{"Path", "User", "URL", "Notes", "Tags", "Rule", "Len", "Hash", "Charset", "LastModified"})
	for _, entry := range entries {
		ss := []string{entry.Path,
			entry.UserName,
			entry.URL,
			entry.Notes,
			strings.Join(entry.Tag, ","),
			entry.Rule,
			strconv.Itoa(entry.Length),
			entry.Hash,
			entry.Charset,
			entry.LastModificationTime.Format(time.DateTime)}
		table.Append(ss)
	}
	table.Render()
}

func initClipboard() {
	// Init returns an error if the package is not ready for use.
	err := clipboard.Init()
	if err != nil {
		panic(err)
	}
}

func writeClipboard(s string) {
	clipboard.Write(clipboard.FmtText, []byte(s))
	fmt.Println("30 seconds later, the clipboard will be cleared")
	time.Sleep(30 * time.Second)
	clipboard.Write(clipboard.FmtText, []byte{})
}
