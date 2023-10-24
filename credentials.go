package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/user"
	"strings"
	"syscall"

	"golang.org/x/term"
)

func credentials() (string, string, error) {
	currentUser, err := user.Current()
	if err != nil {
		log.Fatalf(err.Error())
	}
	name := currentUser.Name

	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Enter Username [default: ", name, "]: ")
	username, err := reader.ReadString('\n')
	if err != nil {
		return "", "", err
	}
	if strings.TrimSpace(username) == "" {
		username = name
	}

	fmt.Print("Enter Password: ")
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return "", "", err
	}

	password := string(bytePassword)
	return strings.TrimSpace(username), strings.TrimSpace(password), nil
}
