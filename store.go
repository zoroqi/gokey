package gokey

import (
	"errors"
	"fmt"
	"github.com/tobischo/gokeepasslib/v3"
	"github.com/tobischo/gokeepasslib/v3/wrappers"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

type EntryInfo struct {
	Path                 string
	Tag                  []string
	Title                string
	URL                  string
	Notes                string
	UserName             string
	LastModificationTime time.Time
	CreationTime         time.Time

	Rule      string
	Length    int
	Password  string
	Charset   string
	Hash      string
	Plaintext string
}

type ConfigInfo struct {
	Charsets          []string
	Version           string
	SupportedHashFunc []string
}

type Tuple[K, V any] struct {
	K K
	V V
}

func TupleOf[K, V any](k K, v V) Tuple[K, V] {
	return Tuple[K, V]{k, v}
}

const (
	index_config      = 0
	index_data        = 1
	index_garbage_can = 2
)

const (
	key_chars = "chars_"
)

var ConfigReservedWord = map[string]bool{
	"Title":     true,
	"UserName":  true,
	"URL":       true,
	"Notes":     true,
	"Charset":   true,
	"Plaintext": true,
	"Rule":      true,
	"Length":    true,
	"Hash":      true,
	"Password":  true,
}

var ErrNotFoundEntry = errors.New("not found")
var ErrNotFoundGroup = errors.New("group not found")
var ErrExists = errors.New("exists")
var ErrIsGroup = errors.New("is a group")
var ErrIsEntry = errors.New("is an entry")
var ErrPath = errors.New("path continues: `" + string(pathInvalidChars) + "`")

var pathInvalidChars = []rune{' ', '"', '\'', '\\', '*', '?', '|', ';', '<', '>', '&', '$', '!', '#', '(', ')', '[', ']', '{', '}'}

const Version = "1.0.0"

// DB represents the KeePass database
type DB struct {
	db *gokeepasslib.Database
}

func (d *DB) getRoot() *gokeepasslib.Group {
	return &d.db.Content.Root.Groups[0]

}

func MkValue(key string, value string) gokeepasslib.ValueData {
	return gokeepasslib.ValueData{Key: key, Value: gokeepasslib.V{Content: value}}
}

func MkProtectedValue(key string, value string) gokeepasslib.ValueData {
	return gokeepasslib.ValueData{
		Key:   key,
		Value: gokeepasslib.V{Content: value, Protected: wrappers.NewBoolWrapper(true)},
	}
}

// NewDB creates a new KDBX V4 database
func NewDB(password string) (*DB, error) {

	dataGroup := gokeepasslib.NewGroup()
	dataGroup.Name = "gokey"
	config := gokeepasslib.NewGroup()
	config.Name = "Config"
	config.Entries = make([]gokeepasslib.Entry, 0)
	versionEntry := gokeepasslib.NewEntry()
	versionEntry.Values = append(versionEntry.Values, MkValue("Title", "Version"))
	versionEntry.Values = append(versionEntry.Values, MkValue("Version", Version))
	config.Entries = append(config.Entries, versionEntry)
	charsetEntry := gokeepasslib.NewEntry()
	charsetEntry.Values = append(charsetEntry.Values, MkValue("Title", "Charsets"))

	for _, v := range chars {
		charsetEntry.Values = append(charsetEntry.Values, MkValue(key_chars+v.name, v.chars))
	}

	config.Entries = append(config.Entries, charsetEntry)
	dataGroup.Groups = append(dataGroup.Groups, config)

	data := gokeepasslib.NewGroup()
	data.Name = "Data"
	dataGroup.Groups = append(dataGroup.Groups, data)

	can := gokeepasslib.NewGroup()
	can.Name = "Garbage Can"
	dataGroup.Groups = append(dataGroup.Groups, can)

	db := gokeepasslib.NewDatabase(gokeepasslib.WithDatabaseKDBXVersion4())
	db.Credentials = gokeepasslib.NewPasswordCredentials(password)
	db.Content.Root.Groups[0] = dataGroup

	return &DB{db: db}, nil
}

// Open opens an existing KDBX file
func Open(path, password string) (*DB, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	db := gokeepasslib.NewDatabase()
	db.Credentials = gokeepasslib.NewPasswordCredentials(password)
	if err := gokeepasslib.NewDecoder(file).Decode(db); err != nil {
		return nil, err
	}
	err = db.UnlockProtectedEntries()
	if err != nil {
		return nil, err
	}
	return &DB{db: db}, nil
}

// Save saves the database to a file
func (d *DB) Save(path string) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()
	err = d.db.LockProtectedEntries()
	if err != nil {
		return err
	}
	return gokeepasslib.NewEncoder(file).Encode(d.db)
}

// CreateEntry creates a new entry at the specified path
func (d *DB) CreateEntry(path string, info EntryInfo) error {
	if !ValidatePath(path) {
		return ErrPath
	}
	group, oldEntry, err := d.findEntry(path, index_data)
	p, entryName := parsePath(path)
	if errors.Is(err, ErrNotFoundGroup) {
		if err := d.createGroup(p, index_data); err != nil {
			return err
		}
	} else if err != nil && !errors.Is(err, ErrNotFoundEntry) {
		return err
	} else if oldEntry != nil {
		return ErrExists
	}

	group, _, err = d.findEntry(path, index_data)
	newEntry := gokeepasslib.NewEntry()
	newEntry.Tags = strings.Join(info.Tag, ",")
	newEntry.Values = append(newEntry.Values,
		MkValue("Title", entryName),
		MkValue("UserName", info.UserName),
		MkValue("URL", info.URL),
		MkValue("Notes", info.Notes),
		MkProtectedValue("Charset", info.Charset),
		MkProtectedValue("Plaintext", info.Plaintext),
		MkProtectedValue("Rule", info.Rule),
		MkProtectedValue("Length", strconv.Itoa(info.Length)),
		MkProtectedValue("Hash", info.Hash),
		MkProtectedValue("Password", info.Password),
	)
	group.Entries = append(group.Entries, newEntry)
	return nil
}

// updateValue updates a specific value in an entry's Values slice
func updateValue(entry *gokeepasslib.Entry, key string, value string, protected bool) {
	for i, v := range entry.Values {
		if v.Key == key {
			entry.Values[i] = gokeepasslib.ValueData{
				Key:   key,
				Value: gokeepasslib.V{Content: value, Protected: wrappers.NewBoolWrapper(protected)},
			}
			return
		}
	}
	entry.Values = append(entry.Values, gokeepasslib.ValueData{
		Key:   key,
		Value: gokeepasslib.V{Content: value, Protected: wrappers.NewBoolWrapper(protected)},
	})
}

// UpdateEntry updates an existing entry at the specified path
func (d *DB) UpdateEntry(path string, info EntryInfo) error {
	if !ValidatePath(path) {
		return ErrPath
	}
	group, entry, err := d.findEntry(path, index_data)
	if err != nil {
		return err
	}
	newEntry := entry.Clone()
	newEntry.Tags = strings.Join(info.Tag, ",")
	updateValue(&newEntry, "Title", info.Title, false)
	updateValue(&newEntry, "UserName", info.UserName, false)
	updateValue(&newEntry, "URL", info.URL, false)
	updateValue(&newEntry, "Notes", info.Notes, false)
	updateValue(&newEntry, "Charset", info.Charset, true)
	updateValue(&newEntry, "Plaintext", info.Plaintext, true)
	updateValue(&newEntry, "Rule", info.Rule, true)
	updateValue(&newEntry, "Length", strconv.Itoa(info.Length), true)
	updateValue(&newEntry, "Hash", info.Hash, true)
	updateValue(&newEntry, "Password", info.Password, true)
	n := wrappers.Now()
	newEntry.Times.LastModificationTime = &n
	if len(newEntry.Histories) == 0 {
		newEntry.Histories = append(newEntry.Histories, gokeepasslib.History{})
	}

	// 旧的 entry 历史信息需要抹除, 不然 KeepassXC 打开文件会异常
	entry.Histories = nil
	newEntry.Histories[0].Entries = append(newEntry.Histories[0].Entries, *entry)
	if len(newEntry.Histories[0].Entries) > 5000 {
		newEntry.Histories[0].Entries = newEntry.Histories[0].Entries[1:]
	}

	// Replace the old entry with the new one
	for i, e := range group.Entries {
		if e.GetTitle() == entry.GetTitle() {
			group.Entries[i] = newEntry
			return nil
		}
	}
	return nil
}

func (d *DB) GetEntry(path string) (EntryInfo, error) {
	_, entry, err := d.findEntry(path, index_data)
	if err != nil {
		return EntryInfo{}, err
	}

	return entryToEntryInfo(*entry, path, true), nil
}

// DeleteEntry deletes an entry at the specified path
func (d *DB) DeleteEntry(path string) error {
	group, _, err := d.findEntry(path, index_data)
	if err != nil {
		return err
	}
	_, entryName := parsePath(path)
	for i, entry := range group.Entries {
		if entry.GetTitle() == entryName {
			group.Entries = append(group.Entries[:i], group.Entries[i+1:]...)
			return nil
		}
	}

	return ErrNotFoundEntry
}

// ChangePassword changes the database password
func (d *DB) ChangePassword(newPassword string) {
	d.db.Credentials = gokeepasslib.NewPasswordCredentials(newPassword)
}

func (d *DB) Search(query []string) []EntryInfo {
	return d.searchRecursive(d.getRoot().Groups[index_data], "", func(path string, entry gokeepasslib.Entry) bool {
		if len(query) == 0 {
			return true
		}
		r := true
		for _, q := range query {
			if q == "" {
				continue
			}
			b := strings.Contains(path, q) ||
				strings.Contains(entry.GetTitle(), q) ||
				strings.Contains(entry.GetContent("UserName"), q) ||
				strings.Contains(entry.Tags, q) ||
				strings.Contains(entry.GetContent("URL"), q) ||
				strings.Contains(entry.GetContent("Notes"), q)
			r = r && b
		}
		return r
	})
}

func (d *DB) searchRecursive(group gokeepasslib.Group, currentPath string,
	match func(string, gokeepasslib.Entry) bool) (results []EntryInfo) {
	for _, entry := range group.Entries {
		if match(currentPath+"/"+entry.GetTitle(), entry) {
			results = append(results, entryToEntryInfo(entry, currentPath+"/"+entry.GetTitle(), false))
		}
	}

	for _, subgroup := range group.Groups {
		results = append(results, d.searchRecursive(subgroup, currentPath+"/"+subgroup.Name, match)...)
	}
	return
}

func entryToEntryInfo(entry gokeepasslib.Entry, path string, getPass bool) EntryInfo {
	e := EntryInfo{
		Path:                 path,
		Title:                entry.GetTitle(),
		URL:                  entry.GetContent("URL"),
		Notes:                entry.GetContent("Notes"),
		UserName:             entry.GetContent("UserName"),
		Tag:                  SplitAndFilterTags(entry.Tags),
		LastModificationTime: entry.Times.LastModificationTime.Time,
		CreationTime:         entry.Times.CreationTime.Time,
		Rule:                 entry.GetContent("Rule"),
		Charset:              entry.GetContent("Charset"),
		Hash:                 entry.GetContent("Hash"),
	}
	e.Length, _ = strconv.Atoi(entry.GetContent("Length"))
	if e.Rule == "pw" {
		e.Length = len(entry.GetContent("Password"))
	}
	if getPass {
		e.Password = entry.GetContent("Password")
		e.Plaintext = entry.GetContent("Plaintext")
	}
	return e
}

func (d *DB) getConfig(key string) (gokeepasslib.Entry, error) {
	configGroup := d.getRoot().Groups[index_config]
	for _, entry := range configGroup.Entries {
		if entry.GetTitle() == key {
			return entry, nil
		}
	}
	return gokeepasslib.NewEntry(), ErrNotFoundEntry
}

func (d *DB) GetConfig(key string) ([]Tuple[string, string], error) {
	configGroup := d.getRoot().Groups[index_config]
	for _, entry := range configGroup.Entries {
		if entry.GetTitle() == key {
			r := []Tuple[string, string]{}
			for _, value := range entry.Values {
				if !ConfigReservedWord[value.Key] {
					r = append(r, TupleOf(value.Key, value.Value.Content))
				}
			}
			return r, nil
		}
	}
	return nil, ErrNotFoundEntry
}

func (d *DB) GetAllConfig() (map[string][]Tuple[string, string], error) {
	configGroup := d.getRoot().Groups[index_config]
	result := map[string][]Tuple[string, string]{}
	for _, entry := range configGroup.Entries {
		r := []Tuple[string, string]{}
		for _, value := range entry.Values {
			if !ConfigReservedWord[value.Key] {
				r = append(r, TupleOf(value.Key, value.Value.Content))
			}
		}
		result[entry.GetTitle()] = r
	}
	return result, nil
}

func (d *DB) GetCharsets() []string {
	c, _ := d.getConfig("Charsets")
	r := []string{}
	for _, value := range c.Values {
		if strings.HasPrefix(value.Key, key_chars) {
			r = append(r, strings.TrimPrefix(value.Key, key_chars))
		}
	}
	return r
}

func (d *DB) DelConfig(config, key string) error {
	if config == "Version" || config == "Title" || config == "Charsets" {
		return fmt.Errorf("config `%s` is reserved", config)
	}
	configGroup := &d.getRoot().Groups[index_config]
	for i, entry := range configGroup.Entries {
		if entry.GetTitle() == config {
			for j, v := range entry.Values {
				if v.Key == key {
					entry.Values = append(entry.Values[:j], entry.Values[j+1:]...)
					configGroup.Entries[i] = entry
					return nil
				}
			}
		}
	}
	return nil
}

func (d *DB) EditConfig(config, key, value string) error {
	if config == "Version" || config == "Title" {
		return fmt.Errorf("config `%s` is reserved", config)
	}
	if config == "Charsets" && !strings.HasPrefix(key, key_chars) {
		key = key_chars + strings.TrimPrefix(key, "_")
	}

	configGroup := &d.getRoot().Groups[index_config]
	for i, entry := range configGroup.Entries {
		if entry.GetTitle() == config {
			for i, v := range entry.Values {
				if config == "Charsets" && v.Key == key {
					return fmt.Errorf("config `%s.%s` is reserved", config, key)
				} else if v.Key == key {
					v.Value.Content = value
					entry.Values[i] = MkValue(key, value)
					return nil
				}
			}
			configGroup.Entries[i].Values = append(configGroup.Entries[i].Values,
				gokeepasslib.ValueData{Key: key, Value: gokeepasslib.V{Content: value}})
			return nil
		}
	}

	entry := gokeepasslib.NewEntry()
	entry.Values = append(entry.Values, MkValue("Title", config))
	entry.Values = append(entry.Values, MkValue(key, value))
	configGroup.Entries = append(configGroup.Entries, entry)
	return nil
}

// createGroup creates a new group at the specified path
func (d *DB) createGroup(parts []string, index int) error {
	if len(parts) == 0 {
		return nil
	}
	// First, validate if we can create the group
	group := &d.getRoot().Groups[index]
	for _, part := range parts {
		found := false
		for _, g := range group.Groups {
			if g.Name == part {
				group = &g
				found = true
				break
			}
		}
		if !found {
			for _, e := range group.Entries {
				if e.GetTitle() == part {
					return ErrIsEntry
				}
			}
		}
	}

	// If we've reached here, we can create the group
	parent := &d.getRoot().Groups[index]
	for _, part := range parts {
		found := false
		for i, g := range parent.Groups {
			if g.Name == part {
				parent = &parent.Groups[i]
				found = true
				break
			}
		}
		if !found {
			parent.Groups = append(parent.Groups, gokeepasslib.NewGroup())
			parent.Groups[len(parent.Groups)-1].Name = part
			parent = &parent.Groups[len(parent.Groups)-1]
		}
	}

	return nil
}

// findEntry locates an entry and its parent group based on the given path
func (d *DB) findEntry(path string, index int) (*gokeepasslib.Group, *gokeepasslib.Entry, error) {
	parts, entryName := parsePath(path)

	group := &d.getRoot().Groups[index]

	// Navigate through the groups
	for i := 0; i < len(parts); i++ {
		found := false
		for j := range group.Groups {
			if group.Groups[j].Name == parts[i] {
				group = &group.Groups[j]
				found = true
				break
			}
		}
		if !found {
			return nil, nil, ErrNotFoundGroup
		}
	}

	for _, group := range group.Groups {
		if group.Name == entryName {
			return nil, nil, ErrIsGroup
		}
	}

	// Find the entry in the last group
	for _, entry := range group.Entries {
		if entry.GetTitle() == entryName {
			return group, &entry, nil
		}
	}

	return group, nil, ErrNotFoundEntry
}

// parsePath splits a path string into a slice of path components and the entry name
func parsePath(s string) ([]string, string) {
	if !strings.HasPrefix(s, "/") {
		s = "/" + s
	}
	parts := strings.Split(s, "/")
	parts = parts[1:]
	if len(parts) == 0 {
		panic("invalid path")
	}
	if len(parts) == 1 {
		return []string{}, parts[0]
	}
	return parts[:len(parts)-1], parts[len(parts)-1]
}

// ValidatePath checks if the given path is valid according to the specified rules
func ValidatePath(path string) bool {
	for _, char := range path {
		for _, invalid := range pathInvalidChars {
			if char == invalid {
				return false
			}
		}
	}
	if strings.HasPrefix(path, "/") {
		path = path[1:]
	}
	parts := strings.Split(path, "/")
	for _, part := range parts {
		if strings.TrimSpace(part) == "" {
			return false
		}
	}

	return true
}

// splitAndFilterTags 将标签字符串分割成切片并过滤掉空标签
func SplitAndFilterTags(tags string) []string {
	// 分割标签
	splitTags := strings.Split(tags, ",")

	// 过滤空标签
	filteredTags := make([]string, 0, len(splitTags))
	for _, tag := range splitTags {
		// 去除首尾空白
		trimmedTag := strings.TrimSpace(tag)
		if trimmedTag != "" {
			filteredTags = append(filteredTags, trimmedTag)
		}
	}

	return filteredTags
}

// ExportEntryHistory exports all historical versions of an entry at the specified path
func (d *DB) ExportEntryHistory(path string) ([]EntryInfo, error) {
	_, entry, err := d.findEntry(path, index_data)
	if err != nil {
		return nil, err
	}

	history := make([]EntryInfo, 0)

	// Add the current version
	history = append(history, entryToEntryInfo(*entry, path, true))

	// Add historical versions
	if len(entry.Histories) > 0 {
		for _, historyEntry := range entry.Histories[0].Entries {
			historyInfo := entryToEntryInfo(historyEntry, path, true)
			history = append(history, historyInfo)
		}
	}

	// Sort the history by LastModificationTime in descending order (newest first)
	sort.Slice(history, func(i, j int) bool {
		return history[i].LastModificationTime.After(history[j].LastModificationTime)
	})

	return history, nil
}
