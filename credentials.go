package main

import (
	"fmt"
	"log"
	"os"
	"os/user"
	"strings"
	"syscall"

	"golang.org/x/term"
)

func credentials() (string, string, error) {
	if strings.TrimSpace(*userSetting) == "" {
		currentUser, err := user.Current()
		if err != nil {
			log.Fatalf(err.Error())
		}
		username = currentUser.Username
	} else {
		username = *userSetting
	}

	fmt.Fprintf(os.Stderr, "Enter Password for %q: ", username)
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return "", "", err
	}

	password := string(bytePassword)
	return strings.TrimSpace(username), strings.TrimSpace(password), nil
}
