package gokey

import (
	"fmt"
	"testing"
)

func Test_GenerateKey(t *testing.T) {
	s := GenerateKey("tuoxin.net", "huangtianhe", 20, GetCharset("default2"), GetHashFunc("SHA512", nil))
	fmt.Println(s)
}

func Test_HashFunctions(t *testing.T) {
	testCases := []struct {
		hashFunc string
		input    string
		expected string
	}{
		{"SHA1", "test", "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"},
		{"SHA224", "test", "90a3ed9e32b2aaf4c61c410eb925426119e1a9dc53d4286ade99a809"},
		{"SHA256", "test", "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"},
		{"SHA384", "test", "768412320f7b0aa5812fce428dc4706b3cae50e02a64caa16a782249bfe8efc4b7ef1ccb126255d196047dfedf17a0a9"},
		{"SHA512", "test", "ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff"},
		{"MD5", "test", "098f6bcd4621d373cade4e832627b4f6"},
	}

	for _, tc := range testCases {
		hashFunc := GetHashFunc(tc.hashFunc, nil)
		result := fmt.Sprintf("%x", hashFunc([]byte(tc.input)))
		if result != tc.expected {
			t.Errorf("Expected %s, but got %s", tc.expected, result)
		}
	}
}
