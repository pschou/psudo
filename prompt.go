package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"
)

func confirm(s string) bool {
	reader := bufio.NewReader(os.Stdin)

	for {
		// sent prompt
		fmt.Printf("%s [y/n]: ", s)

		// read until new line character
		response, err := reader.ReadString('\n')
		if err != nil {
			log.Fatal(err)
		}

		// transpose the response into a trimmed down lower case value
		response = strings.ToLower(strings.TrimSpace(response))

		// verify the response
		if response == "y" || response == "yes" {
			return true
		} else if response == "n" || response == "no" {
			return false
		}
	}
}
