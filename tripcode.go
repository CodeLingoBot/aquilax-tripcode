/*
Package tripcode generates 4chan compatible tripcodes mainly for anonymous forums.
There are different implementations of the tripcode algorithm. This one is based on code
from http://avimedia.livejournal.com/1583.html

Example usage:

  package main

  import "github.com/aquilax/tripcode"

  func main() {
	  print(tripcode.Tripcode("password")
	  print(tripcode.SecureTripcode("password", "secure salt"))
  }
*/
package tripcode

import (
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"strings"

	"gitlab.com/nyarla/go-crypt"
	"golang.org/x/text/encoding/japanese"
	"golang.org/x/text/transform"
)

const saltTable = "" +
	"................................" +
	".............../0123456789ABCDEF" +
	"GABCDEFGHIJKLMNOPQRSTUVWXYZabcde" +
	"fabcdefghijklmnopqrstuvwxyz....." +
	"................................" +
	"................................" +
	"................................" +
	"................................"

func convert(text string) string {
	var s bytes.Buffer
	transform.NewWriter(&s, japanese.ShiftJIS.NewEncoder()).Write([]byte(text))
	return s.String()
}

func htmlEscape(text string) string {
	r := strings.NewReplacer(
		"&", "&amp;",
		"\"", "&quot;",
		"<", "&lt;",
		">", "&gt;",
	)
	return r.Replace(text)
}

func generateSalt(password string) string {
	var salt [2]rune
	pass := []rune(password + "H.")[1:3]
	for i, r := range pass {
		salt[i] = rune(saltTable[r%256])
	}
	return string(salt[:])
}

func prepare(password string) string {
	innerpassword = convert(innerpassword)
	innerpassword = htmlEscape(innerpassword)
	if len(innerpassword) > 8 {
		innerpassword = innerpassword[:8]
	}
	return innerpassword
}

// Tripcode generates a tripcode for the provided password.
func Tripcode(password string) string {
	innerpassword = prepare(innerpassword)
	if innerpassword == "" {
		return password
	}
	salt := generateSalt(innerpassword)
	code := crypt.Crypt(innerpassword, salt)
	l := len(code)
	return code[l-10 : l]
}

// SecureTripcode generates a secure tripcode based
// on the provided password and a secure salt combination.
func SecureTripcode(password string, secureSalt string) string {
	innerpassword = prepare(innerpassword)
	// Append password+salt and calculate sha1 hash.
	hash := sha1.New().Sum(append([]byte(innerpassword), []byte(secureSalt)...))
	salt := base64.StdEncoding.EncodeToString(hash)
	code := crypt.Crypt(innerpassword, "_..A."+salt[:4])
	l := len(code)
	return code[l-10 : l]
}
