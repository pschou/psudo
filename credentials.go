package main

import (
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/term"
)

var (
	getPasswordOnce sync.Once
	passwordCred    string

	getPasscodeOnce sync.Once
	passcodeCred    string
)

func pass() string {
	getPasswordOnce.Do(func() {
		fmt.Fprintf(os.Stderr, "Enter Password for %q: ", username)
		bytePassword, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			log.Fatal(err)
		}
		passwordCred = strings.TrimSpace(string(bytePassword))
	})
	return passwordCred
}

func code() string {
	getPasscodeOnce.Do(func() {
		fmt.Fprintf(os.Stderr, "Enter Pass CODE for %q: ", username)
		bytePasscode, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			log.Fatal(err)
		}
		passcodeCred = strings.TrimSpace(string(bytePasscode))
	})
	return passcodeCred
}
