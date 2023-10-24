package main

import (
	"fmt"

	tsize "github.com/kopoli/go-terminal-size"
)

var term_width, term_height int

func init() {
	s, err := tsize.GetSize()
	if err != nil {
		fmt.Println("Getting terminal size failed:", err)
		return
	}
	term_width, term_height = s.Width, s.Height

	sc, err := tsize.NewSizeListener()
	if err != nil {
		fmt.Println("initializing size listener failed:", err)
		return
	}

	go func() {
		for {
			select {
			case s = <-sc.Change:
				term_width, term_height = s.Width, s.Height
			}
		}
		sc.Close()
		/*for {
			if width, height, err := terminal.GetSize(0); err == nil {
				term_width, term_height = width, height
			}
			time.Sleep(time.Second)
		}*/
	}()
}
