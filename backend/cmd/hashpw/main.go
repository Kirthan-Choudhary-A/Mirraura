// hashpw prints a bcrypt hash for a password, for use in a users.json entry.
//
// Usage: go run ./cmd/hashpw <password>
// or, to avoid the password appearing in shell history:
//
//	echo -n 'the password' | go run ./cmd/hashpw
package main

import (
	"bufio"
	"fmt"
	"os"

	"golang.org/x/crypto/bcrypt"
)

func main() {
	var password string
	if len(os.Args) > 1 {
		password = os.Args[1]
	} else {
		scanner := bufio.NewScanner(os.Stdin)
		if !scanner.Scan() {
			fmt.Fprintln(os.Stderr, "usage: go run ./cmd/hashpw <password>  (or pipe the password on stdin)")
			os.Exit(1)
		}
		password = scanner.Text()
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		fmt.Fprintln(os.Stderr, "hash:", err)
		os.Exit(1)
	}
	fmt.Println(string(hash))
}
