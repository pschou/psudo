package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"regexp"
	"strings"

	ansi "github.com/leaanthony/go-ansi-parser"
	"github.com/remeh/sizedwaitgroup"
	"golang.org/x/crypto/ssh"
)

var (
	hosts               = flag.String("h", "", "Read hosts from given host file")
	script              = flag.String("s", "", "Script to execute remotely")
	parallel            = flag.Int("p", 4, "Maximum concurrent connections allowed")
	identity            = flag.String("i", "", "SSH identity file for login")
	debug               = flag.Bool("d", false, "Turn on script debugging")
	passwordMatch       = flag.String("pw", `^\[sudo\] password for `, "Send password for line matching")
	username, pass      string
	sshInteractiveTries int
	sshWorked           bool
	passwordRegex       *regexp.Regexp
	version             string
)

func main() {
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "Parallel Remote SUDO, Version", version)
		fmt.Fprintln(os.Stderr, "Usage of "+os.Args[0]+":")
		flag.PrintDefaults()
	}
	flag.Parse()
	passwordRegex = regexp.MustCompile(*passwordMatch)

	// Read host list
	hostList, err := readLines(*hosts)
	if err != nil {
		log.Fatal(err)
	}

	// Loop over hosts to verify that the TCP port is connectable
	for i, host := range hostList {
		if _, _, err := net.SplitHostPort(host); err != nil {
			host = net.JoinHostPort(host, "22")
			hostList[i] = host
		}
		conn, err := net.Dial("tcp", host)
		if err != nil {
			log.Fatal(err)
		}
		conn.Close()
	}
	fmt.Println(len(hostList), "hosts loaded")
	//fmt.Printf("%#v\n", hostList)
	if len(hostList) == 0 {
		return
	}

	// Prompt for credentials (for login and sudo)
	username, pass, err = credentials()
	if err != nil {
		log.Fatal(err)
	}
	//fmt.Println("user", username, "pass", pass)

	// Build configuration for ssh
	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.Password(pass),
			ssh.KeyboardInteractive(SshInteractive),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	//fmt.Printf("config %#v\n", config)

	// Parse the identity from the private key for SSH login
	if *identity != "" {
		privateKey, err := os.ReadFile(*identity)
		if err != nil {
			log.Fatal(err)
		}
		key, err := ssh.ParsePrivateKey([]byte(privateKey))
		if err != nil {
			log.Fatal(err)
		}
		config.Auth = append([]ssh.AuthMethod{ssh.PublicKeys(key)}, config.Auth...)
	}

	var (
		checkPassed bool
		checkVerify = make(chan bool)
		swg         = sizedwaitgroup.New(*parallel)
	)

	for _, host := range hostList {
		swg.Add()
		go func(host string) {
			fmt.Println(host, "-- Connecting")
			// Attempt connection into the first host
			client, err := ssh.Dial("tcp", host, config)
			if !checkPassed {
				checkVerify <- err == nil
			}
			if err != nil {
				log.Println(err)
				return
			}
			sshWorked = true

			defer client.Close()

			// Attempt initial send to one client
			err = sendScript(strings.TrimSuffix(host, ":22"), client)
			if err != nil {
				log.Println(host, err)
				return
			}
			swg.Done()
		}(host)

		// Wait for the first connection to succeed before continuing to the rest of the hosts
		if !checkPassed {
			checkPassed = <-checkVerify
			if !checkPassed {
				log.Fatal("error connecting to first host, verify credentials before proceeding")
			}
		}
	}
	swg.Wait()
}

// Send the script over the ssh connection
func sendScript(host string, client *ssh.Client) error {
	{
		session, err := client.NewSession()
		if err != nil {
			return err
		}
		defer session.Close()

		file, err := os.Open(*script)
		if err != nil {
			log.Fatal(err)
		}
		defer file.Close()
		stat, err := file.Stat()
		if err != nil {
			log.Fatal(err)
		}

		file_sent := make(chan error, 1)
		go func() {
			hostIn, err := session.StdinPipe()
			if err != nil {
				file_sent <- err
			}
			defer hostIn.Close()
			fmt.Fprintf(hostIn, "C0600 %d %s\n", stat.Size(), "sudo-ssh-temp")
			_, err = io.Copy(hostIn, file)
			if err != nil {
				file_sent <- err
			}
			fmt.Fprint(hostIn, "\x00")
			file_sent <- err
		}()

		session.Run("/usr/bin/scp -t /tmp/")

		err = <-file_sent
		if err != nil {
			log.Println(host, "Error writing file remotely:", err)
			return err
		}
	}

	{
		session, err := client.NewSession()
		if err != nil {
			return err
		}
		defer session.Close()

		modes := ssh.TerminalModes{
			ssh.ECHO:          0,     // Disable echoing
			ssh.IGNCR:         1,     // Ignore CR on input.
			ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
			ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
		}
		if err := session.RequestPty("xterm", term_width-len(host)-3, term_height, modes); err != nil {
			log.Println(host, "Request for pseudo terminal failed: %s", err)
			return err
		}
		//session.Setenv("SUDO_PROMPT", "SUDO_PASSWORD_PROMPT: ")
		//err = session.Setenv("PS4", "- ${LINENO}/${#BASH_SOURCE}: ")
		//if err != nil {
		//	log.Println(err)
		//}
		stdin, _ := session.StdinPipe()
		stdout, _ := session.StdoutPipe()
		//stderr, _ := session.StderrPipe() // never used, so maybe setup a fifo?
		if *debug {
			session.Start("/usr/bin/bash -c $'PS4=\\'#${LINENO} \\w$ \\' /usr/bin/bash -ex /tmp/sudo-ssh-temp'")
		} else {
			session.Start("/usr/bin/bash -e /tmp/sudo-ssh-temp")
		}

		// Read the input from the reader and print it to the screen
		handler := func(input io.Reader, fd int, c chan bool) {
			buff := new(bytes.Buffer)
			rdr := make([]byte, 32<<10)
			var curStyle = new(ansi.StyledText)
			var doChomp bool
			var hostStyle ansi.TextStyle
			if fd == 1 {
				hostStyle = ansi.Faint
			} else {
				hostStyle = ansi.Bold
			}
			for n, err := input.Read(rdr); n > 0 || err == nil; n, err = input.Read(rdr) {
				//fmt.Printf("read"+num+" %s\n", string(rdr[:n]))
				buff.Write(rdr[:n])
				for {
					str, err := buff.ReadString('\n')
					if doChomp && strings.TrimSpace(str) == "" {
						doChomp = false
						continue
					}
					if passwordRegex.Match([]byte(str)) {
						fmt.Fprintf(stdin, "%s\n", pass)
						if *debug {
							fmt.Println(host, "< sent password to sudo prompt---")
						}
						doChomp = true
						str = ""
					}
					if err == nil {
						// Parse the string to gleen text style for printing
						styledText, _ := ansi.Parse(
							strings.TrimSuffix(ansi.String([]*ansi.StyledText{curStyle}), "\033[0m")+str,
							ansi.WithIgnoreInvalidCodes())
						if len(styledText) > 0 {
							fmt.Printf("%s", ansi.String(append(
								[]*ansi.StyledText{
									&ansi.StyledText{Label: host + " ", Style: hostStyle}},
								styledText...)))

							// Save current style
							curStyle = styledText[len(styledText)-1]
							curStyle.Label = ""
						}
					} else {
						// This may be a partial line, put it back in the buffer and break the loop
						buff.Write([]byte(str))
						break
					}
				}
			}
			c <- true
		}

		a := make(chan bool)
		//a, b := make(chan bool), make(chan bool)
		go handler(stdout, 1, a)
		//go handler(stderr, 2, b)
		session.Wait()
		<-a
		//<-b
	}

	{
		session, err := client.NewSession()
		if err != nil {
			return err
		}
		defer session.Close()
		session.Run("/usr/bin/rm /tmp/sudo-ssh-temp")
	}
	//fmt.Println("returning")
	return nil
}

func SshInteractive(user, instruction string, questions []string, echos []bool) (answers []string, err error) {
	sshInteractiveTries++
	if sshInteractiveTries > 1 && !sshWorked {
		log.Fatal("Bailing out early, password failed once")
	}
	answers = make([]string, len(questions))
	// The second parameter is unused
	for n, _ := range questions {
		answers[n] = pass
	}

	return answers, nil
}
