package gokey

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"sort"
	"strings"
	"time"
)

type Encode string

func (enc Encode) EncodeToString(src []byte) string {
	buf := make([]byte, len(src))
	enc.bsToString(buf, src)
	return string(buf)
}

// 简单的将 []byte 映射成字符串.
func (enc Encode) bsToString(dst, src []byte) {
	chars := []byte(enc)
	for len(chars) < 256 {
		chars = append(chars, chars...)
	}
	for i, b := range src {
		dst[i] = chars[b]
	}
}

type HashFunc func([]byte) []byte

// 为了解决, crypto 函数返回的是数组而不是切片.
// 使用泛型进行统一的类型转换, 因为长度就一下几种, 才可以使用这种方式进行转换.
// 长度来源 crypto.digestSizes
type hashsize interface {
	[]byte | [16]byte | [20]byte | [28]byte | [32]byte | [36]byte | [48]byte | [64]byte
}

type hash struct {
	name     string
	fn       HashFunc
	sequence int
}

var hashfuncs = []hash{
	{"SHA1", arrayToSlice(sha1.Sum), 5},
	{"SHA224", arrayToSlice(sha256.Sum224), 4},
	{"SHA256", arrayToSlice(sha256.Sum256), 3},
	{"SHA384", arrayToSlice(sha512.Sum384), 2},
	{"SHA512", arrayToSlice(sha512.Sum512), 0},
	{"MD5", arrayToSlice(md5.Sum), 1},
}

func GetHashFunc(name string, key []byte) HashFunc {
	for _, v := range hashfuncs {
		if v.name == name {
			return v.fn
		}
	}
	return nil
}

func arrayToSlice[T hashsize](f func([]byte) T) HashFunc {
	return func(data []byte) []byte {
		h := f(data)
		r := make([]byte, len(h))
		for i := 0; i < len(h); i++ {
			r[i] = h[i]
		}
		return r
	}
}

type Encoding interface {
	EncodeToString([]byte) string
}

func GenerateKey(plaintext, salt string, length int, charset Encoding, hashFunc HashFunc) string {
	// 生成签名串
	f := func(s string) string {
		h := hashFunc([]byte(s))
		return charset.EncodeToString(h[:])
	}
	code := f(fmt.Sprintf("%s_%s", plaintext, salt))
	// 截取指定长度的密钥
	for len(code) < length {
		code = f(fmt.Sprintf("%s_%s_%s", plaintext, code, salt)) + code
	}
	truncatedKey := code[:length]
	return truncatedKey
}

const (
	chars_number       = "0123456789"
	chars_lowercase    = "abcdefghijklmnopqrstuvwxyz"
	chars_uppercase    = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	chars_symbols      = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
	chars_less_symbols = "!@#$%,.;'"
)

type charset struct {
	name     string
	chars    string
	sequence int
}

var chars = []charset{
	{"default", chars_number + chars_lowercase + chars_uppercase + strings.Repeat(chars_less_symbols, 3), 0},
	{"num_letter", chars_number + chars_lowercase + chars_uppercase, 1},
	{"num_letter_symbols", chars_number + chars_lowercase + chars_uppercase + chars_symbols, 2},
	{"letter", chars_lowercase + chars_uppercase, 3},
	{"number", chars_number, 4},
	{"lowercase", chars_lowercase, 5},
	{"uppercase", chars_uppercase, 6},
}

func init() {
	sort.Slice(chars, func(i, j int) bool {
		return chars[i].sequence < chars[j].sequence
	})
	sort.Slice(hashfuncs, func(i, j int) bool {
		return hashfuncs[i].sequence < hashfuncs[j].sequence
	})
}

func GetCharset(k string) Encode {
	for _, v := range chars {
		if v.name == k {
			return Encode(v.chars)
		}
	}
	return ""
}

func CharsHelpString() string {
	sb := strings.Builder{}
	for _, v := range chars {
		sb.WriteString(fmt.Sprintf("%s:%s\n", v.name, v.chars))
	}
	return sb.String()
}

func HashHelpString() string {
	sb := strings.Builder{}
	for _, v := range hashfuncs {
		sb.WriteString(fmt.Sprintf("%s\n", v.name))
	}
	return sb.String()
}

func GetAllHashName() []string {
	var keys []string
	for _, v := range hashfuncs {
		keys = append(keys, v.name)
	}
	return keys
}

func RandomKey(length int, charsetName string) string {
	chars := GetCharset(charsetName)
	if chars == "" {
		chars = GetCharset("default")
	}
	s := GenerateKey(
		fmt.Sprintf("%d", time.Now().UnixMicro()),
		fmt.Sprintf("%d", time.Now().UnixMicro()),
		length,
		chars,
		GetHashFunc("SHA512", nil),
	)
	return s
}
